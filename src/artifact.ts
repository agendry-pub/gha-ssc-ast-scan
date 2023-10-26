import * as utils from './utils'
import * as core from '@actions/core'
import * as http from '@actions/http-client'
import fs from 'fs'

async function getAppVersionArtifacts(
  appId: string | number,
  scanType?: string,
  status: string = 'PROCESS_COMPLETE'
): Promise<any> {
  let args = [
    'ssc',
    'artifact',
    'list',
    `--appversion=${appId}`,
    '--output=json'
  ]

  const query = `status=='${status}'${
    scanType ? ` && scanTypes == '${scanType}'` : ''
  }`
  args = args.concat([`-q`, query])

  return await utils.fcli(args)
}

export async function getLatestArtifact(
  appId: string | number,
  scanType: string
): Promise<any> {
  let jsonRes = await getAppVersionArtifacts(appId, scanType)

  return jsonRes[0]
}

export async function getLatestSastArtifact(
  appId: string | number
): Promise<any> {
  let jsonRes = await getAppVersionArtifacts(appId, 'SCA')

  return jsonRes[0]
}

export async function getLatestDastArtifact(
  appId: string | number
): Promise<any> {
  let jsonRes = await getAppVersionArtifacts(appId, 'WEBINSPECT')

  return jsonRes[0]
}

export async function getLatestScaArtifact(
  appId: string | number
): Promise<any> {
  let jsonRes = await getAppVersionArtifacts(appId, 'SONATYPE')

  return jsonRes[0]
}

export async function getScanTypesList(
  appId: string | number
): Promise<string[]> {
  let artifacts = await getAppVersionArtifacts(appId)
  var jp = require('jsonpath')

  const scanTypes = jp
    .query(artifacts, `$.*.scanTypes`)
    .filter(
      (scanType: any, i: any, arr: any[]) =>
        arr.findIndex(t => t === scanType) === i
    )
  utils.debugGroup('scanType:', scanTypes)

  return scanTypes
}

export async function uploadArtifact(
  appId: string | number,
  filePath: string
): Promise<any> {
  try {
    let args = [
      'ssc',
      'artifact',
      'upload',
      `--file=${filePath}`,
      `--appversion=${appId}`,
      // `--engine-type=${engineType}`,
      '--output=json'
    ]

    const response = await utils.fcli(args)

    if (
      ['REQUIRE_AUTH', 'SCHED_PROCESSING', 'PROCESSING', 'PROCESSED'].includes(
        response.status
      )
    ) {
      return response.id
    } else {
      throw new Error(`Artifact Upload finished with status ${response.status}`)
    }
  } catch (e: any) {
    core.error(e.message)
    throw new Error('uploadArtifact failed')
  }
}

export async function downloadArtifact(jobToken: string): Promise<any> {
  try {
    const httpRequest: http.HttpClient = new http.HttpClient()
    httpRequest.requestOptions = {
      headers: {
        'fortify-client': core.getInput('sast_client_auth_token')
      }
    }
    const filePath: string = 'scan.fpr'

    const fpr = fs.createWriteStream(filePath)
    const url: string =
      (await utils.getSastBaseUrl()) + `/rest/v2/job/${jobToken}/FPR`
    let response = await httpRequest.get(url)
    const message = await response.message.pipe(fpr)

    return filePath
  } catch (e: any) {
    core.error(e.message)
    throw new Error('downloadArtifact failed')
  }
}

export async function waitForArtifactUpload(
  artifactId: string | number
): Promise<any> {
  try {
    await utils.fcli(
      [
        'ssc',
        'artifact',
        'wait-for',
        artifactId.toString(),
        // `--while=REQUIRE_AUTH|SCHED_PROCESSING|PROCESSING`,
        `--on-failure-state=terminate`,
        `--on-unknown-state=terminate`,
        `--interval=10s`,
        `--output=expr=Artifact Processing [{id}] ... {status}`
      ],
      true,
      false
    )

    let response = (
      await utils.fcli([
        'ssc',
        'artifact',
        'wait-for',
        artifactId.toString(),
        // `--while=REQUIRE_AUTH|SCHED_PROCESSING|PROCESSING`,'--no-progress',
        `--on-failure-state=terminate`,
        `--on-unknown-state=terminate`,
        `--interval=10s`,
        '--progress=none',
        '--output=json'
      ])
    )[0]

    if (response.status === 'PROCESS_COMPLETE') {
      return { id: response._embed.scans[0].id, date: response.lastScanDate }
    } else {
      throw new Error(
        `Wait-For Artifact Upload finished with status ${response.status}`
      )
    }
  } catch (e: any) {
    core.error(e.message)
    throw new Error('waitForArtifactUpload failed')
  }
}
