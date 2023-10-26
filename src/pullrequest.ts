import * as github from "@actions/github";
import * as core from "@actions/core";
import * as vuln from "./vuln";
import * as utils from "./utils";
import {error} from "@actions/core";
import * as process from "process";

const octokit = github.getOctokit(core.getInput('gha_token'))


async function getSelfCheckRunId(): Promise<number> {
    const {data} = await octokit.request('GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs', {
        owner: github.context.issue.owner,
        repo: github.context.issue.repo,
        run_id: github.context.runId, headers: {
            'X-GitHub-Api-Version': '2022-11-28'
        }
    })

    if (data.total_count) {
        return data.jobs[0].id
    } else {
        throw new Error(`Failed to fetch self job id for run ${github.context.runId} [${github.context.issue.owner}:${github.context.issue.repo}]`)
    }
}


export async function waitForPullRunsCompleted() : Promise<boolean> {
    const selfJobId: number = await getSelfCheckRunId()
    const {data: commits} = await octokit.rest.pulls.listCommits({
        owner: github.context.issue.owner, repo: github.context.issue.repo, pull_number: github.context.issue.number,
    }).catch((error: any) => {
        core.error(error.message)
        throw new Error(`Failed to fetch commit list for pull #${github.context.issue.number} from ${github.context.issue.owner}/${github.context.repo.repo}`)
    })

    utils.debugObject(`Commits count: ${commits.length}`)

    await Promise.all(commits.map(async commit => {
        const {data: checkRuns} = await octokit.request('GET /repos/{owner}/{repo}/commits/{ref}/check-runs?check_name={check_name}', {
            owner: github.context.issue.owner,
            repo: github.context.issue.repo,
            ref: commit.sha,
            check_name: github.context.job,
            headers: {
                'X-GitHub-Api-Version': '2022-11-28'
            }
        })


        await Promise.all(checkRuns.check_runs.map(async function (checkRun: any) {
            if (checkRun.id != selfJobId) {
                let checkRunStatus = checkRun.status
                while (["stale", "in_progress", "queued", "requested", "waiting", "pending"].includes(checkRunStatus)) {
                    core.info(`Waiting for Run : [${checkRun.id}] ${checkRun.name}:${commit.commit.message} [${utils.shortSha(commit.sha)}] to be completed. Curent status: ${checkRun.status}`)
                    await new Promise((resolve) => setTimeout(resolve, Number(utils.getEnvOrValue("GHA_COMMIT_CHECKS_PULL_INTERVAL", 60)) * 1000))

                    const {data: tmp} = await octokit.request('GET /repos/{owner}/{repo}/check-runs/{check_run_id}', {
                        owner: github.context.issue.owner,
                        repo: github.context.issue.repo,
                        check_run_id: checkRun.id,
                        headers: {
                            'X-GitHub-Api-Version': '2022-11-28'
                        }
                    })

                    checkRunStatus = tmp.status
                }

                core.info(`[${checkRun.id}] ${checkRun.name}: ${commit.commit.message} [${utils.shortSha(commit.sha)}] is ${checkRunStatus} `)
            }
        }));

    }))
    return true
}

export async function decorate(appVersionId: string | number): Promise<any> {
    core.info(`Decorating pull request #${github.context.issue.number} from ${github.context.issue.owner}/${github.context.repo.repo}`)

    const {data: commits} = await octokit.rest.pulls.listCommits({
        owner: github.context.issue.owner, repo: github.context.issue.repo, pull_number: github.context.issue.number,
    }).catch((error: any) => {
        core.error(error.message)
        throw new Error(`Failed to fetch commit list for pull #${github.context.issue.number} from ${github.context.issue.owner}/${github.context.repo.repo}`)
    })

    await Promise.all(commits.map(async commit => {
        try {
            utils.debugObject(`Commit SHA: ${commit.sha}`)
            // Get Commit's Files
            const {data: commitData} = await octokit.request(`GET /repos/{owner}/{repo}/commits/{ref}`, {
                owner: github.context.issue.owner, repo: github.context.repo.repo, ref: commit.sha, headers: {
                    'X-GitHub-Api-Version': '2022-11-28'
                }
            })

            const files: any = commitData.files
            let comments: any[] = []
            let vulns: any[] = []

            await Promise.all(files.map(async function (file: any) {
                const regex = /@@\W[-+](?<Left>[,\d]*)\W[-+](?<right>[,\d]*)\W@@/gm
                let m;

                utils.debugGroup(`File: ${file.filename}:`, file)
                while ((m = regex.exec(file.patch)) !== null) {
                    if (m.index === regex.lastIndex) {
                        regex.lastIndex++;
                    }

                    let diffElements: number[] = Array.from(m[2].split(','), Number)
                    const diffHunk: any = {
                        start: diffElements[0], end: diffElements[0] + diffElements[0] - 1
                    }
                    utils.debugObject(`diff: ${file.filename} ${diffHunk.start}:${diffHunk.end}`)

                    const query: string = `[analysis type]:"sca" AND file:"${file.filename}" AND line:[${diffHunk.start},${diffHunk.end}] AND commit:${commit.sha}`
                    let vulns = await vuln.getAppVersionVulns(appVersionId, query , 'id')

                    await vuln.addDetails(vulns, "issueName,traceNodes,fullFileName,shortFileName,brief,friority,lineNumber")

                    vulns.forEach(vuln => {
                        utils.debugGroup(`Adding comment for vuln:`, vuln)
                        const appVersionUrl: string = `${core.getInput('ssc_base_url')}/html/ssc/version/370/audit?q=${vuln?.issueInstanceId}`
                        comments.push({
                            path: file.filename, line: vuln.details.lineNumber, body: `
<p><b>Security Scanning</b> / Fortify SAST</p>
<h3>${vuln.details.friority} - ${vuln.details.issueName} </h3>
<p>${vuln.details.brief}</p>
<br>
<p><a href=${appVersionUrl} target="_blank" rel="noopener noreferrer">More detailed information</a></p>`,
                        })
                    })
                }
            }))

            if (comments.length) {
                utils.debugGroup(`comments:`, comments)
                await octokit.request('POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews', {
                    owner: github.context.issue.owner,
                    repo: github.context.repo.repo,
                    pull_number: github.context.issue.number,
                    commit_id: commit.sha,
                    body: `Fortify found potential problems in commit ${utils.shortSha(commit.sha)}`,
                    event: "COMMENT",
                    comments: comments,
                    headers: {
                        'X-GitHub-Api-Version': '2022-11-28'
                    }
                }).catch(error => {
                    core.error(`${error.message}`)
                    // process.exit(1)
                })
            }
        } catch (error: any) {
            core.warning(`Failed to process commit ${commit.sha}:
                ${error.message}`)
        }
    }))

    core.info("Decoration finished.")
}