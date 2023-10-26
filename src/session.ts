import * as utils from './utils';
import * as core from '@actions/core';

async function hasActiveSscSession(base_url: string): Promise<boolean> {
    try {
        let jsonRes = await utils.fcli([
            'ssc',
            'session',
            'list',
            '-q', 'name==default',
            '--output=json'
        ])

        if (Object.keys(jsonRes).length > 0) {
            if (jsonRes[0]['expired'] != 'Yes') {
                return true
            }
        }

        return false
    } catch (err) {
        core.error('Failed to check existing SSC sessions')
        throw new Error(`${err}`)
    }
}

async function hasActiveSastSession(base_url: string): Promise<boolean> {
    try {
        let jsonRes = await utils.fcli([
            'sc-sast',
            'session',
            'list',
            '-q', 'name==default',
            '--output=json'
        ])

        if (Object.keys(jsonRes).length > 0) {
            if (jsonRes[0]['expired'] != 'Yes') {
                return true
            }
        }

        return false
    } catch (err) {
        core.error('Failed to check existing ScanCentral SAST sessions')
        throw new Error(`${err}`)
    }
}

async function loginSscWithToken(
    base_url: string,
    token: string
): Promise<boolean> {
    try {
        let args = [
            'ssc',
            'session',
            'login',
            `-t`,
            token,
            `--url=${base_url}`,
            '--output=json'
        ]
        args = process.env.FCLI_DISABLE_SSL_CHECKS
            ? args.concat([`--insecure`])
            : args
        let jsonRes = await utils.fcli(args)

        if (jsonRes['__action__'] === 'CREATED') {
            return true
        } else {
            throw new Error(
                `Login Failed: SSC returned __action__ = ${jsonRes['__action__']}`
            )
        }
    } catch (err) {
        throw new Error(`${err}`)
    }
}

async function loginSscWithUsernamePassword(
    base_url: string,
    username: string,
    password: string
): Promise<boolean> {
    let data: any
    try {
        let args = [
            'ssc',
            'session',
            'login',
            `--url`,
            base_url,
            '-u',
            username,
            '-p',
            password,
            '--output=json'
        ]
        args = process.env.FCLI_DEFAULT_TOKEN_EXPIRE
            ? args.concat([`--expire-in=${process.env.FCLI_DEFAULT_TOKEN_EXPIRE}`])
            : args
        args = process.env.FCLI_DISABLE_SSL_CHECKS
            ? args.concat([`--insecure`])
            : args
        data = await utils.fcli(args)
        if (data?.__action__ === 'CREATED') {
            return true
        } else {
            throw new Error(`Login Failed: SSC returned __action__ = ${data?.__action__}`           )
        }
    } catch (err) {
        core.error(utils.failure(`Login to SSC using Username and Password `))
        if (data) {
            utils.errorGroup('data:', data)
        }
        throw err
    }
}

async function loginSastWithToken(
    base_url: string,
    token: string,
    clientToken: string
): Promise<boolean> {

    let args = [
        'sc-sast',
        'session',
        'login',
        `--ssc-url=${base_url}`,
        `--ssc-ci-token=${token}`,
        `--client-auth-token=${clientToken}`,
        '--output=json'
    ]
    args = process.env.FCLI_DISABLE_SSL_CHECKS
        ? args.concat([`--insecure`])
        : args
    let jsonRes = await utils.fcli(args)
    if (jsonRes['__action__'] === 'CREATED') {
        return true
    } else {
        throw new Error(
            `Login Failed: Fortify returned __action__ = ${jsonRes['__action__']}`
        )
    }
}

async function loginSastWithUsernamePassword(
    base_url: string,
    username: string,
    password: string,
    clientToken: string
): Promise<boolean> {
    try {
        let args = [
            'sc-sast',
            'session',
            'login',
            `--ssc-url=${base_url}`,
            `--ssc-user=${username}`,
            `--ssc-password=${password}`,
            `--client-auth-token=${clientToken}`,
            '--output=json'
        ]
        args = process.env.FCLI_DEFAULT_TOKEN_EXPIRE
            ? args.concat([`--expire-in=${process.env.FCLI_DEFAULT_TOKEN_EXPIRE}`])
            : args
        args = process.env.FCLI_DISABLE_SSL_CHECKS
            ? args.concat([`--insecure`])
            : args
        let jsonRes = await utils.fcli(args)
        if (jsonRes['__action__'] === 'CREATED') {
            return true
        } else {
            throw new Error(
                `Login Failed: Fortify returned __action__ = ${jsonRes['__action__']}`
            )
        }
    } catch (err) {
        throw new Error(`${err}`)
    }
}

export async function loginSsc(INPUT: any) {
    core.info(`Login to Software Security Center`)
    /** Login to Software Security Center */
    try {
        if (INPUT.ssc_ci_token) {
            utils.debugObject('Login to Software Security Center using Token')
            await loginSscWithToken(INPUT.ssc_base_url, INPUT.ssc_ci_token)
        } else if (INPUT.ssc_ci_username && INPUT.ssc_ci_password) {
            utils.debugObject('Login to Software Security Center using Username Password')
            await loginSscWithUsernamePassword(
                INPUT.ssc_base_url,
                INPUT.ssc_ci_username,
                INPUT.ssc_ci_password
            )
        } else if (await hasActiveSscSession(INPUT.ssc_base_url)) {
            core.info('Existing default Software Security Center login session found.')
        } else {
            core.info("Login to Software Security Center ..... " + utils.bgRed('Failure'))
            core.error('SSC: Missing credentials. Specify CI Token or Username+Password')
            throw new Error('SSC: Credentials missing and no existing default login session exists')
        }
        core.info("Login to Software Security Center ..... " + utils.bgGreen('Success'))
    } catch (err) {
        core.info("Login to Software Security Center ..... " + utils.bgRed('Failure'))
        core.error(`${err}`)
        throw new Error(`Login to SSC failed!`)
    }
}

export async function loginSast(INPUT: any) {
    core.info(`Login to ScanCentral SAST`)
    /** Login to ScanCentral SAST */
    try {
        if (INPUT.ssc_ci_token) {
            await loginSastWithToken(INPUT.ssc_base_url, INPUT.ssc_ci_token, INPUT.sast_client_auth_token)
        } else if (INPUT.ssc_ci_username && INPUT.ssc_ci_password) {
            await loginSastWithUsernamePassword(
                INPUT.ssc_base_url,
                INPUT.ssc_ci_username,
                INPUT.ssc_ci_password,
                INPUT.sast_client_auth_token
            )
        } else if (await hasActiveSastSession(INPUT.ssc_base_url)) {
            core.info('Existing default ScanCentral SAST login session found.')
        } else {
            core.info("Login to ScanCentral SAST ..... " + utils.bgRed('Failure'))
            core.error('ScanCentral SAST: Missing credentials. Specify CI Token or Username+Password')
            throw new Error('ScanCentral SAST: Credentials missing and no existing default login session exists')
        }
        core.info("Login to ScanCentral SAST ..... " + utils.bgGreen('Success'))
    } catch (err: any) {
        core.info("Login to ScanCentral SAST ..... " + utils.bgRed('Failure'))
        core.error(`${err.message}`)
        throw new Error('Login to ScanCentral SAST failed!')
    }
}
