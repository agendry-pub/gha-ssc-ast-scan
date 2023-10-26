import * as core from '@actions/core'
import * as github from '@actions/github'
import * as vuln from './vuln'
import * as appversion from "./appversion";
import * as filterset from "./filterset";
import * as artifact from "./artifact";
import * as utils from "./utils";
import * as performanceindicator from "./performanceindicator";
import * as process from "process";

function stringToHeader(element: string): string {
    switch (element) {
        case 'Critical':
            return `:red_circle: ${element}`
            break
        case 'High':
            return `:orange_circle: ${element}`
            break
        case 'Medium':
            return `:yellow_circle: ${element}`
            break
        case 'Low':
            return `:white_circle: ${element}`
            break
        default:
            return `:large_blue_circle: ${element}`
            break
    }
}

function getVulnsTotalCountByFolder(vulns: any[], folder: string): number {
    var jp = require('jsonpath')
    const count = jp.query(vulns, `$..[?(@.id=="${folder}")].totalCount`)[0]

    return count ? count : 0
}

function getTotalAndNewCell(count: number, countNew: number): string {
    if (count === 0 || countNew === 0) {
        return `${count}`
    } else if (count === countNew) {
        return `${count} :new:`
    } else {
        return `${count} (${countNew} :new:)`
    }
}

async function getVulnsByScanProductTable(appId: string | number, filterSet: string = "Security Auditor View", newIssues: boolean = false): Promise<any> {
    let headers: any[] = [{data: ':test_tube: Analysis Type', header: true}]
    let rows: any[] = []
    const scanTypesList: string[] = await artifact.getScanTypesList(appId)
    const folders: any[] = await filterset.getFilterSetFolders(appId, filterSet)
    let folderTotals: number[] = []
    let folderTotalsNew: number[] = []

    folders.forEach((folder) => {
        headers.push({data: `${stringToHeader(folder["name"])}`, header: true})
        folderTotals[folder["name"]] = 0
        folderTotalsNew[folder["name"]] = 0
    })
    headers.push({data: `Total`, header: true})

    await Promise.all(scanTypesList.map(async scanType => {
        let total: number = 0
        let totalNew: number = 0
        const vulns = await vuln.getAppVersionVulnsCount(appId, filterSet, scanType, newIssues)
        const vulnsNew = await vuln.getAppVersionVulnsCount(appId, filterSet, scanType, true)

        let row: string[] = [utils.normalizeScanType(scanType)]

        folders.forEach((folder) => {
            const count: number = getVulnsTotalCountByFolder(vulns, folder["name"])
            const countNew: number = getVulnsTotalCountByFolder(vulnsNew, folder["name"])

            total += count
            folderTotals[folder["name"]] += count
            totalNew += countNew
            folderTotalsNew[folder["name"]] += countNew

            row.push(getTotalAndNewCell(count, countNew))
        })
        row.push(getTotalAndNewCell(total, totalNew))
        rows.push(row)
    }))

    let totalRow: string[] = [`Total`]
    let total: number = 0
    let totalNew: number = 0
    folders.forEach((folder) => {
        totalRow.push(getTotalAndNewCell(folderTotals[folder["name"]], folderTotalsNew[folder["name"]]))
        total += folderTotals[folder["name"]]
        totalNew += folderTotalsNew[folder["name"]]
    })
    totalRow.push(getTotalAndNewCell(total, totalNew))
    rows.push(totalRow)

    return [headers].concat(rows)

}

async function getNewVulnsByScanProductTable(appId: string | number, filterSet: string = "Security Auditor View") {
    return await getVulnsByScanProductTable(appId, filterSet, true)
}

async function getNewVulnsTable(appId: string | number, filterSet: string = "Security Auditor View"): Promise<any> {
    var jp = require('jsonpath')

    let headers: any[] = []
    let row: string[] = []
    let total: number = 0
    const folders: any[] = await filterset.getFilterSetFolders(appId, filterSet)
    const vulns = await vuln.getAppVersionNewVulnsCount(appId, filterSet)

    folders.forEach((folder) => {
        headers.push({data: `${stringToHeader(folder["name"])}`, header: true})
        const count = jp.query(vulns, `$..[?(@.id=="${folder["name"]}")].totalCount`)[0]
        row.push(count ? `${count}` : `${0}`)
        total += count ? count : 0
    })

    headers.push({data: `Total`, header: true})
    row.push(`${total}`)

    return [
        headers,
        row
    ]
}

async function getScansSummaryTable(appId: string | number): Promise<any[]> {
    const scanTypesList: string[] = await artifact.getScanTypesList(appId)
    let scanRows: any[] = []

    await Promise.all(
        scanTypesList.map(async scanType => {
            const lastScan = await artifact.getLatestArtifact(appId, scanType)
            const lastDate = new Date(lastScan["lastScanDate"])
            const diffDays = Math.ceil(Math.abs(new Date().getDate() - lastDate.getDate()) / (1000 * 60 * 60 * 24));
            scanRows.push([`<b>Last Successful ${utils.normalizeScanType(scanType)} Scan</b>`, `${lastDate.toLocaleString('fr-FR')} (${utils.daysOrToday(diffDays)})`])
        })
    )

    return scanRows
}

function getAsLink(text: string, link: string): string {
    return `<a target="_blank" href="${link}">${text}</a>`
}

export async function setJobSummary(appVersionId: string | number, passedSecurityage: boolean, summaryFilterSet: string, securityGateFilterSet: string): Promise<any> {
    const securityRating: number = await performanceindicator.getPerformanceIndicatorValueByName(appVersionId, 'Fortify Security Rating')
        .catch(error => {
        core.warning("Failed to get Security Rating")

        return 0
    })
    let n = 0
    const securityStars: string = ":white_circle::white_circle::white_circle::white_circle::white_circle:".replace(/white_circle/g, match => n++ < securityRating ? "star" : match)

    const appVersionUrl: string = `${core.getInput('ssc_base_url')}/html/ssc/version/${appVersionId}/audit`
    const securityRatingsUrl: string = `${core.getInput('ssc_base_url')}/html/ssc/version/${appVersionId}/trend?versionTrendDateRange=YEAR&versionTrendParam=performanceIndicators%3A%3AFortifySecurityRating`
    const securityGateUrl: string = `${core.getInput('ssc_base_url')}/html/ssc/version/${appVersionId}/audit?filterset=${await filterset.getFilterSetGuid(appVersionId, securityGateFilterSet)}`

    await core.summary
        .addImage('https://cdn.asp.events/CLIENT_CloserSt_D86EA381_5056_B739_5482D50A1A831DDD/sites/CSWA-2023/media/libraries/exhibitors/Ezone-cover.png/fit-in/1500x9999/filters:no_upscale()', 'Fortify by OpenText CyberSecurity', {width: "600"})
        .addHeading('Fortify AST Results')
        .addRaw(`:date: Summary Date: ${new Date().toLocaleString('fr-FR')}`)
        .addHeading(':clipboard: Executive Summary', 2)
        .addTable([
            [`<b>Application</b>`, core.getInput('ssc_app'), `<b>Application Version</b>`, `${getAsLink(core.getInput('ssc_version'), appVersionUrl)}`]
        ])
        .addTable([
            [`<p><b>${getAsLink("Fortify Security Rating", securityRatingsUrl)}</b>: ${securityStars}</p>`],
            [`<p><b>${getAsLink("Security Gate Status", securityGateUrl)}</b> :   ${passedSecurityage ? 'Passed :white_check_mark:' : 'Failed :x:'}</p>`]])
        .addTable(await getScansSummaryTable(appVersionId))
        .addHeading(':signal_strength: Security Findings', 2)
        .addRaw(`<p>:telescope: <b>Filter Set</b>: ${summaryFilterSet}</p>`, true)
        .addTable(await getVulnsByScanProductTable(appVersionId, summaryFilterSet))
        .write()
}