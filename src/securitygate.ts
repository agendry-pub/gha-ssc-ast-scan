import * as vuln from "./vuln";
import * as appversion from "./appversion";
import * as core from "@actions/core";

export async function run(appVersionId: string | number, filterSet: string, action: string): Promise<boolean> {
    const count = await vuln.getAppVersionVulnsCountTotal(appVersionId, filterSet)

    const passed: boolean = count ? false : true

    if (!passed) {
        switch (action.toLowerCase()) {
            case 'warn':
                core.info("Security Gate has been set to Warning only")
                core.warning('Security Gate Failure')
                break
            case 'block':
                core.info("Security Gate has been set to Blocking. The job will fail")
                core.setFailed('Security Gate Failure')
                break
        }
    }

    return passed
}