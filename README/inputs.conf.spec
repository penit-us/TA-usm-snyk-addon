[snyk_audit_logs://<name>]
account = Account to use for this input.
index = (Default: default)
interval = Time interval of the data input, in seconds. (Default: 300)
page_limit = Optional. Max pages fetched per run. Leave blank or 0 for unlimited.
updated_after = Optional. ISO-8601 timestamp. Used only if no checkpoint exists yet for this group; defaults to last 24h if left blank.
version = Snyk REST API version, e.g. 2026-03-25. (Default: 2026-03-25)

[snyk_issues://<name>]
account = Account to use for this input.
index = (Default: default)
interval = Time interval of the data input, in seconds. (Default: 900)
page_limit = Optional. Max pages fetched per org per run. Leave blank or 0 for unlimited.
updated_after = Optional. ISO-8601 timestamp. Used only if no checkpoint exists yet for this group; defaults to last 7 days if left blank.
version = Snyk REST API version, e.g. 2026-03-25. (Default: 2026-03-25)

[snyk_projects://<name>]
account = Account to use for this input.
index = (Default: default)
interval = Time interval of the data input, in seconds. (Default: 3600)
page_limit = Optional. Max pages fetched per org per run. Leave blank or 0 for unlimited.
updated_after = Optional. ISO-8601 timestamp filter, if supported by your Snyk API version. Leave blank to always collect the full current project list per org.
version = Snyk REST API version, e.g. 2026-03-25. (Default: 2026-03-25)
