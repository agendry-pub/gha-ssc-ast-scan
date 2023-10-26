import * as utils from './utils'
import * as filterset from './filterset'
import * as core from '@actions/core'
import * as querystring from "querystring";
import {bgYellow} from "./utils";


export async function getAppVersionVulnsCount(appId: number | string, filterSet: string, analysisType?: String, newIssues?: boolean): Promise<any> {
    let query = ""
    if (newIssues) {
        query = "[issue age]:NEW"
    }
    if (analysisType) {
        switch (analysisType) {
            case "SAST":
                query = `${query}${query.length ? " AND " : ""}[analysis type]:SCA`
                break
            case "DAST":
                query = `${query}${query.length ? " AND " : ""}[analysis type]:WEBINSPECT`
                break
            default:
                query = `${query}${query.length ? " AND " : ""}[analysis type]:${analysisType}`
                break
        }
    }
    const url = `/api/v1/projectVersions/${appId}/issueGroups?filterset=${await filterset.getFilterSetGuid(appId, filterSet)}&groupingtype=FOLDER${query.length ? `&qm=issues&q=${encodeURI(query)}` : ""}`

    return await utils.fcliRest(url)
}


export async function getAppVersionNewVulnsCount(appId: number | string, filterSet: string, analysisType?: String): Promise<any> {
    return await getAppVersionVulnsCount(appId, filterSet, analysisType, true)
}

export async function getAppVersionVulnsCountTotal(appId: number | string, filterSet: string, analysisType?: String, newIssues: boolean = false): Promise<any> {
    const count: any[] = await getAppVersionVulnsCount(appId, filterSet, analysisType, newIssues)
    let total: number = 0
    count.forEach(item => {
        total += item["totalCount"]
    })

    return total
}

export async function getVulnsByScanId(appVersionId: number | string, scanId: number | string, fields?: string, newIssues?: boolean): Promise<any> {
    let restQuery: string = ""
    if (newIssues) {
        restQuery = "[issue age]:NEW"
    }
    return await getAppVersionVulns(appVersionId, restQuery, `lastScanId==${scanId}`, fields)
}

export async function getNewVulnsByScanId(appVersionId: number | string, scanId: number | string): Promise<any> {
    return await getVulnsByScanId(appVersionId, scanId, "id,revision,lastScanId", true)
}

export async function getAppVersionVulns(appId: number | string, restQuery?: string, fcliQuery?: string, fields?: string, embed?: string): Promise<any[]> {
    let vulns: any[] = []

    let url: string = `/api/v1/projectVersions/${appId}/issues?`
    url += restQuery ? `q=${encodeURI(restQuery)}&qm=issues&` : ""
    url += fields ? `fields=${fields}&` : ""
    url += embed ? `embed=${embed}&` : ""

    return await utils.fcliRest(url, 'GET', '', fcliQuery)
}

export async function addDetails(vulns: any[], fields?: string): Promise<void> {
    await Promise.all(
        vulns.map(async vuln => {
            const url = `/api/v1/issueDetails/${vuln.id}`
            let data = (await utils.fcliRest(url))[0]
            utils.debugGroup(`Vuln ${vuln.id} details:`, data)

            if (data?.fields) {
                vuln.details = {}
                data.fields.split(",").forEach(function (field: any) {
                    vuln.details[field] = data[field]
                })
            } else {
                vuln.details = data
            }
        })
    )
}

export async function tagVulns(appId: string | number, vulns: any[], guid: string, value: string): Promise<boolean> {
    let body: any = {
        "customTagAudit": {
            "customTagGuid": guid,
            "textValue": value
        },
        "issues": vulns
    }

    return (await utils.fcliRest(`/api/v1/projectVersions/${appId}/issues/action/updateTag`, "POST", JSON.stringify(body))).length > 0
}

export async function transposeToAppVersion(vulns: any, appVersionId: string | number) {
    utils.debugObject(`Transposing vulns to ${appVersionId}`)
    utils.debugObject(`source vulns qty: ${vulns.length}`)
    utils.debugObject(`Getting target vulns`)
    const targetVulns = await getAppVersionVulns(appVersionId, "", "", "id,issueInstanceId,revision")
    utils.debugObject(`target vulns qty: ${targetVulns.length}`)
    var jp = require('jsonpath')

    vulns.forEach(function (vuln: any, index: number, vulns: any[]) {
        const targetVuln = jp.query(targetVulns, `$..[?(@.issueInstanceId=="${vuln.issueInstanceId}")]`)[0]
        if (targetVuln?.id) {
            utils.debugObject(`target vuln found for issueInstanceId ${vuln.issueInstanceId} : ${targetVuln.id} `)
            vuln.id = targetVuln.id
            vuln.revision = targetVuln.revision
        } else {
            utils.debugObject(`target vuln ${bgYellow('not found')} for issueInstanceId ${vuln.issueInstanceId}. Removing it from array `)
            vulns.splice(index, 1)
        }
    })
}

export function getAuditVulnsRequest(appVersionId: string | number, vulns: any[], customTagAudits: any[]) {
    const body: any = {
        "issues": vulns,
        "customTagAudit": customTagAudits
    }

    const uri = `/api/v1/projectVersions/${appVersionId}/issues/action/audit`

    return {
        "httpVerb": "POST",
        "postData": body,
        "uri": core.getInput('ssc_base_url') + uri
    }
}

export async function auditVulns(appVersionId: string | number, vulns: any[], customTagAudits: any[]) {
    let body: any = {
        "issues": vulns,
        "customTagAudit": customTagAudits
    }

    return await utils.fcliRest(`/api/v1/projectVersions/${appVersionId}/issues/action/audit`, "POST", JSON.stringify(body).replace("customTagIndex", "newCustomTagIndex"))

}