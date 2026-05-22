from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    jira_base_url: str
    jira_email: str
    jira_api_token: str
    jira_use_jsm_internal_comments: bool = False

    postgres_dsn: str = "postgresql+psycopg://cve_portal:cve_portal@localhost:5432/cve_portal"
    redis_url: str = "redis://localhost:6379/0"

    nvd_api_key: str | None = None
    redhat_enrichment_enabled: bool = False
    cve5_enrichment_enabled: bool = False

    # Comma-separated lowercase tokens used to decide if an image is a PlainID image.
    # Matched case-insensitively as a substring of image name or tag.
    plainid_image_patterns: str = "agent,pip-operator,pip,pdp,runtime,rclone,secret-mgmt,access-file,authorizer"

    # PLAT “Security Vulnerability” create — `issuetype` name must match Jira exactly (see Project settings).
    jira_plat_project_key: str = "PLAT"
    jira_plat_issuetype_name: str = "Security Vulnerability"
    # If set (e.g. "10034"), `issuetype` is sent as {"id": ...} instead of by name (use when names are ambiguous).
    jira_plat_issuetype_id: str | None = None

    # PLAT Bug create — same project/fields pattern as Security Vulnerability where Jira allows.
    jira_plat_bug_issuetype_name: str = "Bug"
    jira_plat_bug_issuetype_id: str | None = None
    # Bug screen often requires "Dev Group" (PlainID: customfield_10712).
    jira_plat_bug_dev_group_field_id: str = "customfield_10712"
    jira_plat_bug_dev_group_copy_from_source: bool = True
    # When source issue has no Dev Group, use these Jira option label(s) as [{"value": "..."}, ...] (comma-separated for multi).
    jira_plat_bug_dev_group_option_value: str = "BE"
    # Jira Components on PLAT Bug create (e.g. Security).
    jira_plat_bug_component_name: str = "Security"

    jira_plat_cf_cve_id: str = "customfield_11245"
    jira_plat_cve_cf_number: int = 11245

    # PLAT correlation custom field (imagename_CVE-…) — PlainID uses `customfield_10744`.
    # Must not match any id in `jira_plat_organization_field_id` (comma-separated list).
    jira_plat_cf_internal_id: str = "customfield_10744"
    jira_plat_cf_package_name: str = "customfield_11243"
    jira_plat_cf_package_vuln_version: str = "customfield_11246"
    # Fallback sent when affected_version is unknown but Jira requires the field.
    jira_plat_package_vuln_version_fallback: str = "N/A"
    # PLAT Security Vulnerability: “Tag numbers” (PlainID customer field) — read on sync.
    jira_plat_tag_numbers_field_id: str = "customfield_11210"

    # PLAT Organization CF — PlainID expects `[{"value": "CustomerName"}]` on `customfield_10727` (create + edit).
    # Comma-separated for mirrors; optional merge appends more CF ids (deduped).
    jira_plat_organization_field_id: str = "customfield_10727"
    jira_plat_organization_field_id_merge: str = ""
    jira_plat_extra_organizations: str = ""
    jira_plat_use_source_issue_organizations: bool = True
    # When copying from the portal parent (`source_issue_key`), also call `GET /rest/servicedeskapi/request/{key}`
    # if `/rest/api/3/issue` yields no Organization (JSM often exposes it there).
    jira_plat_try_jsm_request_api_for_organization: bool = True
    jira_plat_resolve_organizations_via_servicedesk: bool = True
    # If true, omit Organization (customfield) on create — only if Jira allows missing Organization.
    jira_plat_skip_organization_field_on_create: bool = False
    # When false (default), we never POST without Organization if we have ids — Jira often requires it as an array.
    jira_plat_try_bare_create_then_set_organization: bool = False
    # When true, drop Organization *name* refs that fail the check below (id-only refs are always kept).
    jira_plat_restrict_organization_names_to_enum: bool = False
    # Comma-separated Organization *display names* as in Jira/JSM (e.g. Accenture,Novartis).
    # When non-empty and restrict flag is true, only these names pass (case-insensitive). When empty and restrict
    # is true, falls back to `PlatOrganizationLabel` in code. Prefer this env list so you do not need a code change
    # for every new customer org.
    jira_plat_organization_name_allowlist: str = ""
    # Extra CF ids (comma-separated) to request on GET issue when copying Organization from the parent ticket
    # so we do not miss data that lives on `customfield_10403`. Set empty to disable extras (unusual).
    jira_plat_organization_read_field_ids_extra: str = "customfield_10403"
    # When no org is found on the payload, source issue, or JIRA_PLAT_EXTRA_ORGANIZATIONS, use these names for
    # `customfield_10727` as `[{"value": "<name>"}]` (comma-separated). Example: `Humana`
    jira_plat_default_organization_names: str = ""

    # After creating (or reusing) a PLAT ticket, link it to the source PLATFORM issue via issueLink.
    # Set to false to disable without code changes.
    jira_plat_link_to_parent_on_create: bool = True
    # Jira issue-link type name used for the PLATFORM → PLAT relationship.
    jira_plat_parent_link_type_name: str = "Relates"

    # Extra fields included inline on PLAT issue create (both Security Vulnerability and Bug).
    # Account picker field — set to {"accountId": <value>} when non-empty.
    jira_plat_cf_account_field_id: str = "customfield_10650"
    jira_plat_cf_account_id: str | None = None
    # Team/squad select field — set to {"value": <value>} when non-empty.
    jira_plat_cf_team_field_id: str = "customfield_10776"
    jira_plat_cf_team_value: str | None = None


settings = Settings()

