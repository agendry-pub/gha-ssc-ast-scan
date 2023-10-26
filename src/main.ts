import * as core from '@actions/core'
import * as session from './session'
import * as appversion from './appversion'
import * as sast from './sast'
import * as summary from './summary'
import * as securitygate from './securitygate'
import * as customtag from './customtag'
import * as vuln from './vuln'
import * as utils from './utils'
import * as pullrequest from './pullrequest'
import * as process from "process";
import * as github from "@actions/github";
import * as artifact from "./artifact";

const INPUT = {
    ssc_base_url: core.getInput('ssc_base_url', {required: true}),
    ssc_ci_token: core.getInput('ssc_ci_token', {required: false}),
    ssc_ci_username: core.getInput('ssc_ci_username', {required: false}),
    ssc_ci_password: core.getInput('ssc_ci_password', {required: false}),
    ssc_app: core.getInput('ssc_app', {required: true}),
    ssc_version: core.getInput('ssc_version', {required: false}),
    ssc_source_app: core.getInput('ssc_source_app', {required: false}),
    ssc_source_version: core.getInput('ssc_source_version', {required: false}),
    ssc_source_copy_vulns: core.getInput('ssc_source_copy_vulns', {required: false}),
    ssc_commit_customtag_guid: core.getInput('ssc_commit_customtag_guid', {required: true}),
    sast_scan: core.getBooleanInput('sast_scan', {required: false}),
    sast_client_auth_token: core.getInput('sast_client_auth_token', {required: false}),
    sast_build_options: core.getInput('sast_build_options', {required: false}),
    security_gate_action: core.getInput('security_gate_action', {required: false}),
    security_gate_filterset: core.getInput('security_gate_filterset', {required: false}),
    summary_filterset: core.getInput('summary_filterset', {required: false}),
    gha_token: core.getInput('gha_token', {required: false}),
}

/**
 * The main function for the action.
 * @returns {Promise<void>} Resolves when the action is complete.
 */
export async function run(): Promise<void> {
    try {
        /** Login */
        await session.loginSsc(INPUT).catch(error => {
            core.setFailed(`${error.message}`)
            process.exit(core.ExitCode.Failure)
        })
        if(INPUT.sast_scan){
            await session.loginSast(INPUT).catch(error => {
                core.setFailed(`${error.message}`)
                process.exit(core.ExitCode.Failure)
            })
        }

        /** PR handling
         * - Waits for completion of PR's commit
         * - Define PR's AppVersion to the base branch
         * */
        if (github.context.eventName === "pull_request") {
            core.info("Pull Request detected")
            core.info("Waiting for PR's related commits check runs to complete")
            const completed: boolean | void = await pullrequest.waitForPullRunsCompleted().catch(error => {
                core.warning(`Something went wrong while waiting for PR's related commits check runs to complete: ${error.message}`)
            })
            if (completed) {
                core.info("All PR's related commits check runs are completed")
            } else {
                core.warning("All PR's related commits check runs did not complete")
            }
            if (github.context.payload.pull_request) {
                INPUT.ssc_source_app = INPUT.ssc_app
                INPUT.ssc_source_version = github.context.payload.pull_request.head.ref
            }
        }

        /** Does the AppVersion exists ? */
        const appVersionId = await appversion.getOrCreateAppVersionId(INPUT.ssc_app, INPUT.ssc_version, INPUT.ssc_source_app, INPUT.ssc_source_version)

        /** SAST Scan Execution */
        if (INPUT.sast_scan) {
            /** Source code packaging */
            core.info(`Packaging source code with "${INPUT.sast_build_options}"`)
            const packagePath = "package.zip"
            await sast.packageSourceCode(INPUT.sast_build_options, packagePath).then(packaged => {
                if (packaged != 0) {
                    throw new Error(utils.failure(`Packaging source code with "${INPUT.sast_build_options}"`))
                }
            }).catch(error => {
                core.error(error.message)
                core.setFailed(utils.failure(`Packaging source code with "${INPUT.sast_build_options}"`))
                process.exit(core.ExitCode.Failure)
            })
            core.info(utils.success(`Packaging source code with "${INPUT.sast_build_options}"`))

            /** SAST scan submisison */
            core.info(`SAST scan submission`)
            const jobToken: string = await sast.startSastScan(packagePath).catch(error => {
                core.error(error.message)
                core.setFailed(utils.failure(`SAST scan submission`))
                process.exit(core.ExitCode.Failure)
            })
            core.info(utils.success(`SAST scan submission`))
            core.info(`SAST scan execution (jobToken: ${jobToken})`)
            await sast.waitForSastScan(jobToken).then(result => {
                if (!result) {
                    throw new Error(utils.failure(`SAST scan execution (jobToken: ${jobToken})`))
                } else {
                    core.info(utils.success(`SAST scan execution (jobToken: ${jobToken})`))
                }
            }).catch(error => {
                core.error(error.message)
                core.setFailed(utils.failure(`SAST scan execution (jobToken: ${jobToken})`))
                process.exit(core.ExitCode.Failure)
            })

            core.info(`Artifact Download (jobToken: ${jobToken})`)
            const fprPath = await artifact.downloadArtifact(jobToken).catch(error => {
                core.error(error.message)
                core.setFailed(utils.failure(`Artifact Download (jobToken: ${jobToken})`))
                process.exit(core.ExitCode.Failure)
            })
            core.info(utils.success(`Artifact Download (jobToken: ${jobToken})`))

            core.info(`Artifact Upload to ${INPUT.ssc_app}:${INPUT.ssc_version} [${appVersionId}]`)
            const artifactId = await artifact.uploadArtifact(appVersionId, fprPath).catch(error => {
                core.error(error.message)
                core.setFailed(utils.failure(`Artifact Upload to ${INPUT.ssc_app}:${INPUT.ssc_version} [${appVersionId}]`))
                process.exit(core.ExitCode.Failure)
            })
            core.info(utils.success(`Artifact Upload to ${INPUT.ssc_app}:${INPUT.ssc_version} [${appVersionId}]`))

            core.info(`Artifact Processing [${artifactId}]`)
            const scan = await artifact.waitForArtifactUpload(artifactId).catch(error => {
                core.error(error.message)
                core.setFailed(utils.failure(`Artifact Processing [${artifactId}]`))
                process.exit(core.ExitCode.Failure)
            })
            core.info(utils.success(`Artifact Processing [${artifactId}]`))
            core.info(utils.success(`Scan ${scan.id} execution, upload, processing`))

            try {
                core.info(`Tagging Vulns with commit SHA (${github.context.sha})`)
                const scanVulns = await vuln.getNewVulnsByScanId(appVersionId, scan.id)
                if (scanVulns.length) {
                    const customTagGuid = core.getInput("ssc_commit_customtag_guid")
                    core.info(`Checking if ${INPUT.ssc_app}:${INPUT.ssc_version} [${appVersionId}] has Commit CustomTag (guid: ${customTagGuid})`)
                    if (!await appversion.appVersionHasCustomTag(appVersionId, customTagGuid)
                        .catch(error => {
                            core.error(utils.failure(`Checking if ${INPUT.ssc_app}:${INPUT.ssc_version} [${appVersionId}] has Commit CustomTag (guid: ${customTagGuid})`))
                            throw error
                        })) {
                        core.info(`AppVersion ${INPUT.ssc_app}:${INPUT.ssc_version} [${appVersionId}] ${utils.bgYellow('does not have Commit CustomTag')} (guid: ${customTagGuid})`)
                        core.info(`Checking if CustomTag exists in Templates (guid: ${customTagGuid})`)
                        if (await customtag.commitCustomTagExists(customTagGuid)
                            .catch(error => {
                                core.error(utils.failure(`Checking if CustomTag exists in Templates (guid: ${customTagGuid})`))
                                throw error
                            })) {
                            core.info(utils.exists(`Checking if CustomTag exists in Templates (guid: ${customTagGuid})`))
                            core.info(`Adding CustomTag ${customTagGuid} to ${INPUT.ssc_app}:${INPUT.ssc_version} [${appVersionId}]`)
                            await appversion.addCustomTag(appVersionId, customTagGuid)
                                .catch(error => {
                                    core.error(utils.failure(`Adding CustomTag ${customTagGuid} to ${INPUT.ssc_app}:${INPUT.ssc_version} [${appVersionId}]`))
                                    throw error
                                })
                            core.info(utils.success(`Adding CustomTag ${customTagGuid} to ${INPUT.ssc_app}:${INPUT.ssc_version} [${appVersionId}]`))
                        }
                    }
                    await vuln.tagVulns(appVersionId, scanVulns, customTagGuid, github.context.sha)
                        .catch(error => {
                            throw error
                        })
                } else {
                    core.notice(`Current Fortify scan found no ${utils.bgBlue('NEW')} vulnerability`)
                    core.info(utils.skipped(`Tagging Vulns with commit SHA (${github.context.sha})`))
                }
            } catch (error: any) {
                core.error(utils.failure(`Tagging Vulns with commit SHA (${github.context.sha})`))
            }

        }
        if (github.context.eventName === 'pull_request') {
            core.info("Pull Request Detected")

            await pullrequest.decorate(appVersionId)
        }

        /** RUN Security Gate */
        core.info("Security Gate execution")
        const passedSecurityGate = await securitygate.run(appVersionId, INPUT.security_gate_filterset, INPUT.security_gate_action)
            .catch(error => {
                core.error(error.message)
                core.setFailed(utils.failure(`Security Gate execution`))
                process.exit(core.ExitCode.Failure)
            })
        core.info(utils.success("Security Gate execution"))

        /** Job Summary */
        core.info(`Job Summary generation`)
        await summary.setJobSummary(appVersionId, passedSecurityGate, INPUT.summary_filterset, INPUT.security_gate_filterset)
            .catch(error => {
                core.error(error.message)
                core.warning(utils.failure(`Job Summary generation`))
            })
        core.info(utils.success(`Job Summary generation`))

        core.setOutput('time', new Date().toTimeString())
    } catch (error) {
        // Fail the workflow run if an error occurs
        if (error instanceof Error) core.setFailed(error.message)
    }
}
