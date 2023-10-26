# Run a SAST Scan with Fortify Software Security Center

Build secure software fast with [Fortify](https://www.microfocus.com/en-us/solutions/application-security). Fortify offers end-to-end application security solutions with the flexibility of testing on-premises and on-demand to scale and cover the entire software development lifecycle.  With Fortify, find security issues early and fix at the speed of DevOps.

This GitHub Action utilizes [fcli](https://github.com/fortify/fcli) [v2.x.x] to achieve the following :
- Login to Software Security Center and ScanCentral SAST
- Create the Application Version in Fortify Software Security Center. Option to copy the status (Attributes, Vulns and Audit) from another Application Version
- Run a synchronous SAST Scan
- Decorate the GitHub Job Summary with any type of scan
- Decorate the GitHub Pull Request's Conversation and Commits

## Table of Contents

* [Requirements](#requirements)
    * [Fortify instance](#fortify-instance)
    * [Network connectivity](#network-connectivity)
    * [fcli](#fcli)
* [Usage](#usage)
    * [Complete Action Definition Sample](#complete-action-definition-sample)
        * [SSC Inputs](#ssc-inputs)
* [Environment Variables](#environment-variables)
* [Information for Developers](#information-for-developers)

## Requirements

### Fortify instance
Obviously you will need to have a Fortify instance (On-prem or Hosted) from with Software Security Center and ScanCentral SAST. If you are not already a Fortify customer, check out our [Free Trial](https://www.microfocus.com/en-us/products/application-security-testing/free-trial).

### Network connectivity
The Fortify instance to which you wants to connect needs to be accessible from the GitHub Runner executing the action. Following table lists some considerations:

| Source  | Runner        | Considerations                                                                                                                                                                                                                                                                                                                          |
|---------| ------------- |-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Fortify | GitHub-hosted | GitHub lists [IP addresses for GitHub-hosted runners](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners#ip-addresses) that need to be allowed network access to Fortify. Exposing a Fortify instance to the internet, even if limited to only GitHub IP addresses, could pose a security risk. |
| Fortify     | Self-hosted   | May need to allow network access from the self-hosted runner to Fortify if in different network segments                                                                                                                                                                                                                                |

### fcli

This action uses [fcli](https://github.com/fortify/fcli) [v2.x.x] for most of its call to Software Security Center. Either use the [OpenText Official Docker Image](https://hub.docker.com/r/fortifydocker/fortify-ci-tools): `
fortifydocker/fortify-ci-tools`. Or download the cli in you jobs (feel free to change the version upwards):

```bash
  - name: Download fcli
    run: |
      wget -qO- https://github.com/fortify/fcli/releases/download/v2.0.0/fcli-linux.tgz | tar zxf -  
```

### scancentral

This action uses [scancentral](https://www.microfocus.com/documentation/fortify-software-security-center/2310/SC_SAST_Help_23.1.0/index.htm#Gen_SC_Package.htm?TocPath=Submitting%2520Scan%2520Requests%257C_____3) 
cli to package the source code. Either use the [OpenText Official Docker Image](https://hub.docker.com/r/fortifydocker/fortify-ci-tools): `
fortifydocker/fortify-ci-tools`.

You can also install it using [fcli](https://github.com/fortify/fcli)
```bash
      # Java is required to run ScanCentral Client, and may be required for your build
      # Java version to use depends on the Java version required to run your build (if any),
      # and the Java version supported by the ScanCentral Client version that you are running
      - name: Setup Java
        uses: actions/setup-java@v3
        with:
          java-version: 11

      ### Set up Fortify ScanCentral Client ###
      - name: Download Fortify ScanCentral Client
        run: |
          fcli tool scancentral-client install --client-auth-token=${{ secrets.FTFY_SAST_CLIENT_TOKEN }}
```

You can also set it up using [OpenText Official GitHub Action](https://github.com/marketplace/actions/fortify-scancentral-scan):

```bash
      # Java is required to run ScanCentral Client, and may be required for your build
      # Java version to use depends on the Java version required to run your build (if any),
      # and the Java version supported by the ScanCentral Client version that you are running
      - name: Setup Java
        uses: actions/setup-java@v3
        with:
          java-version: 11

      ### Set up Fortify ScanCentral Client ###
      - name: Download Fortify ScanCentral Client
        uses: fortify/gha-setup-scancentral-client@v1   
        with:
          version: 23.1.0                                      # You should specify a client version that matches their ScanCentral environment
          client-auth-token: ${{ secrets.FTFY_SAST_CLIENT_TOKEN }} 
```

### Commit Custom Tag

This GitHub Action requires a Custom Tag to follow which commit first introduced each vulnerability.\
You should create this using the following command:
```bash
fcli ssc rest call /api/v1/customTags -X POST -d '{
    "customTagType": "CUSTOM",
    "guid": "bc16a10e-1b08-4516-80a1-f0b4ff4a3e9d",
    "name": "Commit",
    "valueType": "TEXT"
}'
```
Feel free to change the name of the CustomTag, **BUT if you decide to change the Guid or create the CustomTag from the UI, then you need to set the input `ssc_commit_customtag_guid`**


## Usage

This GitHub Action achieves the following :
- Login to Software Security Center and ScanCentral SAST
- Create the Application Version in Fortify Software Security Center. Option to copy the status (Attributes, Vulns and Audit) from another Application Version
- Run a synchronous SAST Scan
- Decorate the GitHub Job Summary
- Decorate the GitHub Pull Request's Conversation and Commits

### Complete Action Definition Sample

This example workflow demonstrates how to use the full capacity of this GitHub Action\
**Note**: Make sure your variable `sast_build_options` are correctly set. For build options examples, please refer to the [OpenText Official Documentation](https://www.microfocus.com/documentation/fortify-software-security-center/2310/SC_SAST_Help_23.1.0/index.htm#Gen_SC_Package.htm?TocPath=Submitting%2520Scan%2520Requests%257C_____3)

```yaml
name: (FTFY) Fortify Application Security
on: 
  workflow dispatch :
  push :
  pull_request:
      
jobs:                                                  
  FortifySASTScan:
    runs-on: ubuntu-latest
    
    container:
      image: fortifydocker/fortify-ci-tools

    permissions: write-all
    env:
      APPLICATION: "${{ github.event.repository.name }}"
      VERSION: "${{ github.ref_name }}"

    steps:
      # Pull SAST issues from Fortify on Demand and generate GitHub-optimized SARIF output
      - name: Fortify SAST Scan
        uses: agendry-pub/gha-ssc-ast-scan@v1
        env:
          FCLI_DEFAULT_TOKEN_EXPIRE: "1h"
        with:
          ssc_base_url: ${{ vars.FTFY_SSC_BASE_URL}}
          ssc_app: ${{ env.APPLICATION }}
          ssc_version: ${{ env.VERSION }}
          ssc_version_attributes: |
            Accessibility=Internal Network Access Required
            DevStrategy=Internally Developed
            DevPhase=New
            Interfaces=Programmatic API,Web Access
          ssc_version_issue_template: Prioritized High Risk Issue Template
          ssc_source_version: ${{ github.event.repository.default_branch }}
          ssc_source_copy_vulns: true
          ssc_ci_username: ${{ secrets.FTFY_CI_USERNAME }}
          ssc_ci_password:  ${{ secrets.FTFY_CI_PASSWORD }}
          sast_scan: true
          sast_client_auth_token: ${{ secrets.FTFY_SAST_CLIENT_TOKEN }}
          sast_build_options: "-bt mvn -q"
          security_gate_action: warn
          security_gate_filterset: Critical & High
          summary_filterset: Security Auditor View
          gha_token: ${{ secrets.GITHUB_TOKEN }}
      
```


#### Considerations

* FCLI supports Fortify Token in Decoded and Encoded format
* Username and Password are required to copy the application version state from another one. The CI Token does not have the required permissions. Unified Login Token is the only type of token, but has a maximum expiration of 1 day
* if you specify the source app:version, only the Rules, Tags and BugTracker settings will be copied. Set `copy_vulns` to `true`if you want to copy the Vulnerability and Audit values as well


#### SSC Inputs

**`ssc_url`**  *Required*\
The base URL for the Fortify Software Security Center instance where your data resides.

**`ssc_ci_token` OR `ssc_ci_username` + `ssc_ci_password`**   *Optional*\
Credentials for authenticating to Software Security Center. If both methods provided, the Action will choose the Token. Strongly recommend use of GitHub Secrets for credential management. \
If an existing and valid default session exists in the local fcli context, this default session will be used.

**`ssc_app`**  *Optional*\
The target SSC application name to create.\
Default: `github.event.repository.name` (GitHub repository name )

**`ssc_version`**  *Optional*\
The target SSC application version name to create\
Default: `github.ref_name` (GitHub branch name)

**`ssc_version_attributes`**   *Optional*\
The target SSC application version attributes to be assigned. \
This is a multiline input using the fcli syntax for attributes updates : `fcli ssc attribute update -h`\
List of available attributes: `fcli ssc attribute list-definitions` (add `-o json`to get list of available values)
```yaml
ssc_version_attributes: |
    Accessibility=Internal Network Access Required
    DevStrategy=Internally Developed
    DevPhase=New
```
**Notes**:
* Attributes assignment will happen after source application Copy State
* By default, the above attributes are required when creating an application. This can be disable in SSC > Administration > Templates > Attributes

**`ssc_version_issue_template`**  *Optional*\
The target SSC application version issue template to be assigned.\
Example:
```yaml
ssc_version_issue_template: PCI v4.0 Basic Issue Template
```
**Notes**:
* Issue template assignment will happen after source application Copy State
* By default, an issue template is required when creating an application. However, you can define a default template in SSC > Administration > Templates > Issue Templates

**`ssc_source_app`**   *Optional*\
The source SSC application name to copy from\
Default: if `ssc_source_version` is set, then value of `ssc_app`

**`ssc_source_version`**   *Optional*\
The source SSC application version name to copy from

**`copy_vulns`**   *Optional*\
Enable to copy vulnerabilities from source to target application version

**`ssc_commit_customtag_guid`**   *Optional*\
Guid of the CustomTag used to store the Commit SHA that introduced the vulnerability.
You should have created it using the following command:
```bash
fcli ssc rest call /api/v1/customTags -X POST -d '{
    "customTagType": "CUSTOM",
    "guid": "bc16a10e-1b08-4516-80a1-f0b4ff4a3e9d",
    "name": "Commit",
    "valueType": "TEXT"
}'
```
Feel free to change the name of the CustomTag, **BUT if you decide to change the Guid, then you need to set this input**\
Default: `bc16a10e-1b08-4516-80a1-f0b4ff4a3e9d`

**`sast_scan`**   *Optional*\
Set to false to disable sast scan\
Default: `true`

**`sast_client_auth_token`**   *Optional*\
Fortify ScanCentral SAST Client auth token. This token is set at installation time. Contact your administrator to get this value.\
This is not a token generated from Software Security Center\
**Note**: Is required if `sast_scan` is set to `true`

**`sast_build_options`**   *Optional*\
Build options used by the `scancentral` cli to package the source code.\
For build options examples, please refer to the [OpenText Official Documentation](https://www.microfocus.com/documentation/fortify-software-security-center/2310/SC_SAST_Help_23.1.0/index.htm#Gen_SC_Package.htm?TocPath=Submitting%2520Scan%2520Requests%257C_____3)\
Default: `true`

**`security_gate_action`**   *Optional*\
Warn or Block on Security Gate Failure.\
Default: `warn`

**`security_gate_action`**   *Optional*\
FilterSet used for the Security Gate.\
Default: `Security Auditor View`

**`summary_filterset`**   *Optional*\
FilterSet used in the Job Summary.\
Default: `Security Auditor View`

**`gha_token`**   *required*\
GHA Token used to request GitHub API\
Should be set to `${{ secrets.GITHUB_TOKEN }}`


## Environment Variables

**`FCLI_DEFAULT_TOKEN_EXPIRE`**   *Optional*\
Overrides default sessions token lifespan/expiration. Specifies for how long the session should remain active, for example 1h (1 hour), 1d (1 day) \
Default: 1d\
**Note**: Only apply to Username/Password logins

**`FCLI_EXECUTABLE_LOCATION`**   *Optional*\
Set the location where the fcli executable is located\
Default: None

**`FCLI_EXECUTABLE_PATH`**   *Optional*\
Set the full path to the fcli executable \
Default: None

**`FCLI_DISABLE_SSL_CHECKS`**   *Optional*\
Disable SSL checks when fcli logs in to SSC (adds the `--insecure` to the fcli command) \
Default: false

## Information for Developers

All commits to the `main` branch should follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) convention. In particular, commits using the `feat: Some feature` and `fix: Some fix` convention are used to automatically manage version numbers and for updating the [CHANGELOG.md](https://github.com/fortify/gha-export-vulnerabilities/blob/master/CHANGELOG.md) file.

Whenever changes are pushed to the `main` branch, the [`.github/workflows/publish-release.yml`](https://github.com/fortify/gha-ssc-create-application-version/blob/main/.github/workflows/publish-release.yml) workflow will be triggered. If there have been any commits with the `feat:` or `fix:` prefixes, the [`release-please-action`](https://github.com/google-github-actions/release-please-action) will generate a pull request with the appropriate changes to the CHANGELOG.md file and version number in `package.json`. If there is already an existing pull request, based on earlier feature or fix commits, the pull request will be updated.

Once the pull request is accepted, the `release-please-action` will publish the new release to the GitHub Releases page and tag it with the appropriate `v{major}.{minor}.{patch}` tag. The two `richardsimko/update-tag` action instances referenced in the `publish-release.yml` workflow will create or update the appropriate `v{major}.{minor}` and `v{major}` tags, allowing users to reference the action by major, minor or patch version.