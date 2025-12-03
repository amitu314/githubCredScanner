`` This script will work for check sensitive credentials in repositories inside an organization Account. ``
Sensitive information this script would check

- Azure Storage Key
- Client Secret
- AccountKey
- Bearer key
- ssh-rsa
- JWT
- Password

This script is intended for particular use-cases. More use-cases may be added


## How to run the scripts

- First run the cloneRepoOrgAcc script. This will clone all the repos from an Org account to a particular folder.
- Then, run the checkCred script to get sensitive creds in the files under the repo (by OS walk)

## What you will need?

- You will need Github_API token and will need to set up either using  `export GITHUB_TOKEN='testtestestest'` or `$Env=GITHUB_TOKEN='testtesteest'`
- Install ``pip install GitPython``
