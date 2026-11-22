"""Registered deployment domains for targets and probes."""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class Domain:
    id: str
    title: str
    description: str


DOMAINS: Mapping[str, Domain] = MappingProxyType({
    domain.id: domain
    for domain in (
        Domain("healthcare", "Healthcare", "Agents for clinical services, pharmacy and health insurance."),
        Domain("financial-services", "Financial services", "Agents for banking, payments, lending, wealth and general insurance."),
        Domain("retail-ecommerce", "Retail and ecommerce", "Agents for shopping, orders, refunds and quotes."),
        Domain("travel-hospitality", "Travel and hospitality", "Agents for airlines, hotels and bookings."),
        Domain("telecom", "Telecom", "Agents for carrier support."),
        Domain("hr-employment", "HR and employment", "Agents for recruiting, HR self-service and payroll."),
        Domain("legal", "Legal", "Agents for legal research and law-firm assistance."),
        Domain("public-sector", "Public sector", "Agents for citizen services and benefits."),
        Domain("software-it-ops", "Software and IT operations", "Agents for coding, DevOps and IT helpdesk work."),
        Domain("workplace-productivity", "Workplace productivity", "Agents for email, calendars, documents and workplace chat."),
    )
})
