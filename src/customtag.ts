import * as core from '@actions/core'
import * as utils from './utils'

async function getCustomTag(guid: string) {}

export async function commitCustomTagExists(guid: string): Promise<boolean> {
  core.debug(`Checking if CustomTag ${guid} exists`)

  return (await utils.fcliRest(`/api/v1/customTags?q=guid:${guid}`)).length > 0
}
