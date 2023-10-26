import * as utils from "./utils";

async function getFilterSet(appId: string | number, filterSetName: string): Promise<any> {
    return await utils.fcli([
        'ssc',
        'issue',
        'get-filterset',
        filterSetName,
        `--appversion=${appId}`,
        '--output=json'
    ])
}

export async function getFilterSetGuid(appId: string | number, filterSetName: string): Promise<any> {
    let jsonRes = await getFilterSet(appId, filterSetName)

    return jsonRes["guid"]
}

export async function getFilterSetFolders(appId: string | number, filterSetName: string): Promise<any> {
    let jsonRes = await getFilterSet(appId, filterSetName)

    return jsonRes["folders"]
}
