# ---------------------------------------------------------------------------
# Microsoft Entra External ID (CIAM) — replaces Azure AD B2C
# ---------------------------------------------------------------------------
# Azure AD B2C is no longer available for new tenants (deprecated May 2025).
# Use Microsoft Entra External ID instead.
#
# MANUAL STEP (Terraform cannot create CIAM tenants):
#   1. Azure Portal → Microsoft Entra External ID → Create tenant
#      - Tenant type: "Customer" (CIAM)
#      - Domain: yourtenant-dev.onmicrosoft.com
#   2. Record tenant_id and tenant subdomain
#   3. Set in terraform.tfvars:
#        ciam_tenant_id   = "<guid>"
#        ciam_tenant_name = "argusdev"
#   4. Run: terraform apply
#
# The app registrations are created automatically in b2c_apps.tf
# ---------------------------------------------------------------------------
