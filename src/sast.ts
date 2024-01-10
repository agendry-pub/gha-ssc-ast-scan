import * as utils from './utils'
import * as core from '@actions/core'

export async function packageSourceCode(
  buildOpts: string,
  packagePath: string
): Promise<number> {
  return await utils.scancentral(
    ['package'].concat(
      utils.stringToArgsArray(buildOpts).concat(['-o', packagePath])
    ),
    !core.isDebug()
  )
}

export async function startSastScan(packagePath: string): Promise<string> {
  let jsonRes = await utils.fcli([
    'sc-sast',
    'scan',
    'start',
    // '--no-upload',
    // '--upload',
    // `--appversion=${app}:${version}`,
    `--sensor-version=23.2.0`,
    `--package-file=${packagePath}`,
    '--output=json'
  ])

  if (jsonRes['__action__'] == 'SCAN_REQUESTED') {
    core.debug(`Scan ${jsonRes['jobToken']} requested`)
    return jsonRes['jobToken']
  } else {
    throw new Error(
      `Scan submission failed: Fortify returned ${jsonRes['__action__']}`
    )
  }
}

export async function waitForSastScan(jobToken: string): Promise<boolean> {
  await core.group(`SAST scan execution (jobToken: ${jobToken})`, async () => {
    await utils.fcli(
      [
        'sc-sast',
        'scan',
        'wait-for',
        jobToken,
        // `--status-type=scan`, `--while=PENDING|QUEUED|RUNNING`,
        `--interval=1m`,
        `--on-failure-state=terminate`,
        `--on-unknown-state=terminate`,
        `--output=expr=SAST scan execution (jobToken: {jobToken}) ... {scanState}`
      ],
      true,
      false
    )
  })
  let data = await utils.fcli([
    'sc-sast',
    'scan',
    'wait-for',
    jobToken,
    // `--status-type=scan`, `--while=PENDING|QUEUED|RUNNING`, '--no-progress'
    `--interval=1m`,
    '--progress=none',
    '--output=json',
    `--on-failure-state=terminate`,
    `--on-unknown-state=terminate`
  ])

  data = data[0]

  if (
    data['scanState'] === 'COMPLETED'
    // && jsonRes['sscUploadState'] === 'COMPLETED'
    // && jsonRes['sscArtifactState'] === 'PROCESS_COMPLETE'
  ) {
    utils.debugObject(`Scan ${data['jobToken']} COMPLETED`)
    return true
  } else if (data['scanState'] != 'COMPLETED') {
    throw new Error(
      `Scan execution failed: Fortify returned scanState=${data['scanState']}`
    )
  } else if (data['sscUploadState'] != 'COMPLETED') {
    throw new Error(
      `Scan upload failed: Fortify returned sscUploadState=${data['scanState']}`
    )
  } else if (data['sscArtifactState'] != 'PROCESS_COMPLETE') {
    throw new Error(
      `Scan artifact processing failed: Fortify returned sscArtifactState=${data['scanState']}`
    )
  } else {
    throw new Error(`Scan failed: Fortify returned ${data['__action__']}`)
  }

  return false
}
