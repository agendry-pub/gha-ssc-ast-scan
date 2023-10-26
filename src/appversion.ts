import * as utils from './utils'
import * as vuln from './vuln'
import * as core from '@actions/core'
import process from "process";

export async function getAppVersion(app: string, version: string) : Promise<any> {
    return (await utils.fcli([
        'ssc',
        'appversion',
        'list',
        `-q`, `application.name=='${app}'&&name=='${version}'`,
        '--output=json'
    ]))[0]
}
export async function getAppVersionId(app: string, version: string): Promise<number> {
    const appVersion: any = await getAppVersion(app, version)

    return appVersion?.id
}

async function getAppVersionCustomTags(appVersionId: string | number, fields?: string): Promise<any> {
    const url = `/api/v1/projectVersions/${appVersionId}/customTags?${fields ? `fields=${fields}&` : ""}`
    return await utils.fcliRest(url)

}

export async function appVersionExists(app: string, version: string): Promise<boolean> {
    return (await getAppVersionId(app, version)) > 0
}

async function commitAppVersion(id: string): Promise<boolean> {
    utils.debugObject(`Committing AppVersion ${id}`)

    const commitBodyJson = JSON.parse(`{"committed": "true"}`)

    return await utils.fcliRest(`/api/v1/projectVersions/${id}`, 'PUT', JSON.stringify(commitBodyJson))
}

async function setAppVersionIssueTemplate(appId: string, template: string): Promise<boolean> {
    let jsonRes = await utils.fcli([
        'ssc',
        'appversion',
        'update',
        `--issue-template=${template}`,
        `${appId}`,
        '--output=json'
    ])

    if (jsonRes['__action__'] === 'UPDATED') {
        return true
    } else {
        core.warning(
            `Issue Template update failed: SSC returned __action__ = ${jsonRes['__action__']}`
        )
        return false
    }
}

async function setAppVersionAttribute(appId: string, attribute: string): Promise<boolean> {
    try {
        let jsonRes = await utils.fcli([
            'ssc',
            'appversion-attribute',
            'set',
            attribute,
            `--appversion=${appId}`,
            '--output=json'
        ])

        return true
    } catch (err) {
        core.error('Something went wrong during Application Attribute assignment')
        throw new Error(`${err}`)
    }
}

async function setAppVersionAttributes(appId: string, attributes: string[]): Promise<boolean> {
    utils.debugObject(`Setting AppVersion ${appId} attributes`)
    utils.debugObject(`Attributes Qty: ${attributes.length}`)
    utils.debugGroup(`Attributes:`,attributes)
    await Promise.all(
        attributes.map(async attribute => {
            utils.debugObject(`Assigning ${attribute} to ${appId}`)
            let status = await setAppVersionAttribute(appId, attribute)
            utils.debugObject(`Assigned = ${status}`)
            if (!status) {
                core.warning(`Attribute assignment failed: ${attribute}`)
                return false
            }
        })
    )

    return true
}

async function copyAppVersionVulns(source: string | number, target: string | number): Promise<boolean> {
    utils.debugObject(`Copying AppVersion Vulnerabilities ${source} -> ${target}`)
    const copyVulnsBodyJson = utils.getCopyVulnsBody(source, target)


    const data = (await utils.fcliRest('/api/v1/projectVersions/action/copyCurrentState','POST', JSON.stringify(copyVulnsBodyJson)))[0]
    if(200 <= data?.responseCode && data?.responseCode <300 ){
        return true
    } else {
        throw new Error(`copyAppVersionVulns failed with response: ${data}`)
    }
}


async function copyAppVersionState(source: string, target: string): Promise<any> {
    utils.debugObject(`Copying AppVersion State ${source} -> ${target}`)
    const copyStateBodyJson = utils.getCopyStateBody(source, target)

    const data = (await utils.fcliRest('/api/v1/projectVersions/action/copyFromPartial', 'POST', JSON.stringify(copyStateBodyJson)))[0]
    if(200 <= data?.responseCode && data?.responseCode <300 ){
        return true
    } else {
        throw new Error(`copyAppVersionState failed with response: ${data}`)
    }

}

async function copyAppVersionAudit(source: string | number, target: string | number): Promise<boolean> {
    var jp = require('jsonpath')
    utils.debugObject(`Copying AppVersion Audit values ${source} -> ${target}`)
    utils.debugObject(`Get CustomTag list from AppVersion ${source}`)
    const customTags = await getAppVersionCustomTags(source, "id,guid,name,valueType,valueList")
    utils.debugObject(`CustomTags Qty: ${customTags.length}`)
    utils.debugObject(`Get vulns list from Source AppVersion ${source}`)
    const vulns = await vuln.getAppVersionVulns(source, "", "", "id,issueInstanceId,revision", "auditValues")
    utils.debugObject(`transpose to appversion ${target}`)
    await vuln.transposeToAppVersion(vulns, target)

    let requests: any[] = []
    await Promise.all(
        vulns.map(async function (vulnTmp: any) {
            // const customTagUniqueValues: string[] = Array.from(new Set(jp.query(vulns, `$..[?(@.customTagGuid=="${customTag.guid}")].textValue`)))
            if (vulnTmp._embed.auditValues.length) {
                requests.push(vuln.getAuditVulnsRequest(
                    target,
                    [{
                        "id": vulnTmp.id,
                        "revision": vulnTmp.revision
                    }],
                    vulnTmp._embed.auditValues))
            }

        })
    )

    await utils.fcliRest("/api/v1/bulk", "POST", JSON.stringify({"requests": requests}))

    return true
}


async function deleteAppVersion(id: any): Promise<boolean> {
    utils.debugObject(`Deleting AppVersion ${id}`)

    return await utils.fcliRest(`/api/v1/projectVersions/${id}`, 'DELETE')

}

async function getAppId(app: string): Promise<number> {
    let jsonRes = await utils.fcli([
        'ssc',
        'app',
        'ls',
        `-q`,`name=='${app}'`,
        '--output=json'
    ])

    if (jsonRes.length === 0) {
        utils.debugObject(`Application ${app} not found`)
        return -1
    } else {
        utils.debugObject(`Application ${app} exists`)
        return jsonRes[0].id
    }
}

async function createAppVersion(app: any, version: string): Promise<any> {
    utils.debugObject(`Creating AppVersion ${app}:${version}`)

    const appId = await getAppId(app)
    let createAppVersionBodyJson
    if (appId > 0) {
        utils.debugObject(`Application ${app} exists`)
        createAppVersionBodyJson = utils.getCreateAppVersionBody(appId, version)
    } else {
        utils.debugObject(`Application ${app} not found. Creating new Application as well`)
        createAppVersionBodyJson = utils.getCreateAppVersionBody(app, version)
    }

    return (await utils.fcliRest('/api/v1/projectVersions', 'POST', JSON.stringify(createAppVersionBodyJson)))[0]
}

export async function addCustomTag(appId: number | string, customTagGuid: string): Promise<boolean> {
    const url = `/api/v1/projectVersions/${appId}/customTags`
    const body = {
        guid: customTagGuid
    }

    return (await utils.fcliRest(url,"POST", JSON.stringify(body))).length > 0
}

async function runAppVersionCreation(app: string, version: string, source_app?: string, source_version?: string): Promise<number> {
    core.info(`ApplicationVersion ${app}:${version} creation`)
    const appVersion = await createAppVersion(app, version)
        .catch(async function(error) {
            core.error(`${error.message}`)
            throw new Error(utils.failure(`ApplicationVersion ${app}:${version} creation`))
        })
    core.info(utils.success(`ApplicationVersion ${app}:${version} creation`))
    core.info(`AppVersion ${appVersion.project.name}:${appVersion.name} created with id: ${appVersion.id}`)

    /** COPY STATE: run the AppVersion Copy  */
    let sourceAppVersionId
    if (source_version) {
        source_app = source_app ? source_app : app
        core.info(`Copy state from ${source_app}:${source_version} to ${app}:${version}`)
        sourceAppVersionId = await getAppVersionId(source_app, source_version)
            .catch(error => {
                core.warning(`Failed to get ${source_app}:${source_version} id`)
                core.warning(`${error.message}`)
            })
        if (sourceAppVersionId) {
            await copyAppVersionState(sourceAppVersionId.toString(), appVersion.id)
                .then(() =>
                    core.info(utils.success(`Copy state from ${source_app}:${source_version} to ${app}:${version}`)))
                .catch(error => {
                    core.warning(`${error.message}`)
                    core.warning(utils.failure(`Copy state from ${source_app}:${source_version} to ${app}:${version}`))
                })
        } else {
            core.info(`Source AppVersion ${source_app}:${source_version} not found`)
            core.warning(utils.skipped(`Copy state from ${source_app}:${source_version} to ${app}:${version}` ))
        }
    }

    /** ISSUE TEMPLATE : set AppVersion Issue template */
    core.info("Setting AppVersion's Issue Template")
    await setAppVersionIssueTemplate(appVersion.id, core.getInput('ssc_version_issue_template'))
        .then(() => core.info(utils.success(`Setting AppVersion's Issue Template to ${app}:${version}`)))
        .catch(error => {
            core.warning(`${error.message}`)
            core.warning(utils.failure(`Setting AppVersion's Issue Template to ${app}:${version}`))
            // process.exit(core.ExitCode.Failure)
        })

    /** ATTRIBUTES : set AppVersion attributes */
    core.info("Setting AppVersion's Attributes")
    await setAppVersionAttributes(appVersion.id, core.getMultilineInput('ssc_version_attributes'))
        .then(() => core.info(utils.success(`Setting AppVersion's Attributes to ${app}:${version}`)))
        .catch(error => {
            core.warning(`${error.message}`)
            core.warning(utils.failure(`Setting AppVersion's Issue Template to ${app}:${version}`))
            // process.exit(core.ExitCode.Failure)
        })

    /** COMMIT: Commit the AppVersion */
    core.info(`Committing AppVersion ${appVersion.project.name}:${appVersion.name} (id: ${appVersion.id})`)
    await commitAppVersion(appVersion.id)
        .then(() => core.info(utils.success(`Committing AppVersion ${appVersion.project.name}:${appVersion.name} (id: ${appVersion.id})` )))
        .catch(async function (error) {
            core.error(error.message)
            core.error(utils.failure(`Committing AppVersion ${appVersion.project.name}:${appVersion.name} (id: ${appVersion.id})`))

            /** delete uncommited AppVersion */
            core.info("Trying to delete uncommitted version")
            await deleteAppVersion(appVersion.id)
                .catch(error => {
                    core.error(`Failed to delete uncommited version ${appVersion.project.name}:${appVersion.name} [id: ${appVersion.id}`)
                })
            throw new Error(`Failed to commit AppVersion ${appVersion.project.name}:${appVersion.name} (id: ${appVersion.id})`)
        })

    /** COPY VULNS: run the AppVersion Copy vulns */
    if (core.getInput('ssc_source_copy_vulns') && sourceAppVersionId) {
        core.info(`Copy Vulnerabilities from ${source_app}:${source_version} to ${app}:${version}`)
        if (await copyAppVersionVulns(sourceAppVersionId, appVersion.id)) {
            core.info(utils.success(`Copy Vulnerabilities from ${source_app}:${source_version} to ${app}:${version}` ))

            core.info(`Copy Audit from ${source_app}:${source_version} to ${app}:${version}`)
            await copyAppVersionAudit(sourceAppVersionId, appVersion.id)
                .then(() => core.info(utils.success(`Copy Audit from ${source_app}:${source_version} to ${app}:${version}`)))
                .catch(error => {
                    core.warning(`${error.message}`)
                    core.warning(utils.failure(`Copy Audit from ${source_app}:${source_version} to ${app}:${version}`))
                    // process.exit(core.ExitCode.Failure)
                })
        } else {
            core.warning(utils.failure(`Copy Vulnerabilities from ${source_app}:${source_version} to ${app}:${version}`))
            core.info(utils.skipped(`Copy Vulnerabilities from ${source_app}:${source_version} to ${app}:${version}`))
        }
    }

    return appVersion.id
}

export async function getOrCreateAppVersionId(app: string, version: string, source_app?: string, source_version?: string): Promise<number> {
    core.info(`Retrieving AppVersion ${app}:${version}`)
    let appVersionId = await getAppVersionId(app, version)
        .catch(error => {
            core.error(`${error.message}`)
            throw new Error(utils.failure(`Retrieving AppVersion ${app}:${version}`))
        })

    if (appVersionId === undefined || appVersionId === -1) {
        core.info(utils.notFound(`Retrieving AppVersion ${app}:${version}`))
        appVersionId = await runAppVersionCreation(app, version, source_app, source_version)
            .catch(error => {
                core.error(error.message)
                core.setFailed(`Failed to create application version ${app}:${version}`)
                process.exit(core.ExitCode.Failure)
            })
        core.info(`Application Version ${app}:${version} created (${appVersionId})`)
    } else {
        core.info(utils.exists(`Retrieving AppVersion ${app}:${version}`))
    }

    return Number(appVersionId)
}

export async function appVersionHasCustomTag(AppVersionId: string | number, customTagGuid: string): Promise<boolean> {
    // Can be used to get it using App and version names : project.name:"Bench"+AND+name:"1.0"
    return (await utils.fcli(
        ['ssc', 'appversion', 'list',
            `--q-param=id:${AppVersionId}`,
            `--embed=customTags`,
            `--output=json`,
            `-q`, `customTags.![guid].contains('${customTagGuid}')`])).length > 0
}