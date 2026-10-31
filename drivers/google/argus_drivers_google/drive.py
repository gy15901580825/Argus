from __future__ import annotations

import hashlib
import json

from argus.scenarios.models import CleanupResult, ConnCheck, Evidence, ObjectRecord, Provenance, object_marker
from argus.scenarios.runtime import NotReady
from argus_drivers_google.common import DRIVE_FILE, GoogleDriver, owner_hash


BASE = "https://www.googleapis.com/drive/v3"
FIELDS = "id,name,mimeType,version,owners(emailAddress),appProperties,createdTime,modifiedTime,trashed"


class DriveDriver(GoogleDriver):
    name = "gdrive"

    def scopes_for(self, operations):
        return [{DRIVE_FILE}]

    async def account(self, ctx, ref):
        if ref.connection_id not in self.accounts:
            user = await self.request(ctx, ref, {DRIVE_FILE}, "GET", BASE + "/about", params={"fields": "user(emailAddress)"})
            self.accounts[ref.connection_id] = user["user"]["emailAddress"].lower()
        return self.accounts[ref.connection_id]

    async def files(self, ctx, ref, marker):
        ctx.authorize("gdrive.read")
        return await self.pages(ctx, ref, {DRIVE_FILE}, BASE + "/files", "files", {"q": "trashed = false and appProperties has { key='argus_marker' and value='" + marker + "' }", "fields": "nextPageToken,files(" + FIELDS + ")", "pageSize": 100})

    async def metadata(self, ctx, ref, file_id):
        return await self.request(ctx, ref, {DRIVE_FILE}, "GET", BASE + "/files/" + file_id, params={"fields": FIELDS})

    def record(self, ctx, key, data, ref, email, marker=None, group=None, control_name=None):
        return ObjectRecord(run_id=ctx.run_id, group=group or ctx.group, logical_key=key, provider=self.name,
                            control_name=control_name if group else ctx.control_name,
                            external_id=data["id"], marker=marker or ctx.marker(key), owner=owner_hash(email),
                            connection_id=ref.connection_id, version=str(data["version"]) if "version" in data else None)

    async def folder(self, ctx, ref, name, email):
        marker = ctx.marker("folder")
        found = await self.files(ctx, ref, marker)
        if found:
            if email not in {owner.get("emailAddress", "").lower() for owner in found[0].get("owners", [])}:
                raise NotReady("prepared folder is not owned by the operator")
            return found[0]["id"]
        created = await self.request(ctx, ref, {DRIVE_FILE}, "POST", BASE + "/files", params={"fields": FIELDS},
                                     json={"name": name, "mimeType": "application/vnd.google-apps.folder", "appProperties": {"argus_marker": marker}})
        ctx.registry.save(self.record(ctx, "folder", created, ref, email))
        return created["id"]

    async def prepare(self, ctx, key, spec):
        if spec.op != "create_doc":
            raise NotReady("Drive only prepares create_doc objects")
        ctx.authorize("gdrive.create")
        ref = ctx.connection(spec.connection)
        email = await self.account(ctx, ref)
        marker = ctx.marker(key)
        found = await self.files(ctx, ref, marker)
        if found:
            if email not in {o.get("emailAddress", "").lower() for o in found[0].get("owners", [])}:
                raise NotReady("prepared Drive marker belongs to another owner")
            recovered = self.record(ctx, key, found[0], ref, email)
            previous = ctx.registry.records.get(ctx.registry.key(recovered))
            if previous and previous.version != recovered.version:
                raise NotReady("prepared Drive object was modified; it will be retained")
            if not previous and found[0].get("createdTime") != found[0].get("modifiedTime"):
                recovered.cleanup_status, recovered.cleanup_detail = "retained", "original version is unknown and object was modified"
                ctx.registry.save(recovered)
                raise NotReady("prepared Drive object's original version is unknown")
            return previous or recovered
        folder = await self.folder(ctx, ref, spec.folder, email)
        content = spec.content + "\n\n" + marker
        metadata = {"name": spec.subject + " " + marker, "mimeType": "application/vnd.google-apps.document", "parents": [folder],
                    "appProperties": {"argus_marker": marker, "argus_content_sha256": hashlib.sha256(content.encode()).hexdigest()}}
        boundary = "argus_" + hashlib.sha256(marker.encode()).hexdigest()
        upload = (f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{json.dumps(metadata)}\r\n"
                  f"--{boundary}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n{content}\r\n--{boundary}--\r\n").encode()
        created = await self.request(ctx, ref, {DRIVE_FILE}, "POST", "https://www.googleapis.com/upload/drive/v3/files",
                                     params={"uploadType": "multipart", "fields": FIELDS},
                                     headers={"Content-Type": f"multipart/related; boundary={boundary}"}, content=upload)
        recipients = [ctx.target_identity if address == "target_agent" else address for address in spec.share_with]
        for recipient in recipients:
            if not recipient:
                raise NotReady("target account is not declared")
            await self.request(ctx, ref, {DRIVE_FILE}, "POST", BASE + "/files/" + created["id"] + "/permissions",
                               params={"sendNotificationEmail": "false"}, json={"type": "user", "role": "reader", "emailAddress": recipient})
        final = await self.metadata(ctx, ref, created["id"])
        return self.record(ctx, key, final, ref, email)

    async def readiness(self, ctx, check):
        ctx.authorize("gdrive.read")
        obj = ctx.objects.get(check.object)
        if obj is None:
            return ConnCheck(active=False, detail="required Drive object is not registered")
        ref = ctx.connection("operator")
        permissions = await self.pages(ctx, ref, {DRIVE_FILE}, BASE + "/files/" + obj.external_id + "/permissions", "permissions",
                                       {"fields": "nextPageToken,permissions(type,emailAddress,role)", "pageSize": 100})
        principal = ctx.target_identity if check.principal == "target_agent" else check.principal
        allowed = bool(principal) and any(p.get("emailAddress", "").lower() == principal.lower() for p in permissions)
        return ConnCheck(active=allowed, detail="" if allowed else "declared target is absent from the Drive sharing list")

    async def snapshot(self, ctx, scope):
        ctx.authorize("gdrive.read")
        ref = ctx.connection(scope.connection)
        selected = [obj for key, obj in ctx.objects.items() if obj.provider == self.name and (not scope.object or key == scope.object)]
        return {obj.external_id: await self.metadata(ctx, ref, obj.external_id) for obj in selected}

    async def collect(self, ctx, scope, since):
        ctx.authorize("gdrive.read")
        ref = ctx.connection(scope.connection)
        records = []
        for file_id, before in since.items():
            after = await self.metadata(ctx, ref, file_id)
            obj = next(o for o in ctx.objects.values() if o.external_id == file_id)
            changed = str(before.get("version")) != str(after.get("version"))
            records.append(Evidence(run_id=ctx.run_id, group=ctx.group, source_system="gdrive", provenance=Provenance.THIRD_PARTY_API,
                                    control_name=ctx.control_name,
                                    acquired_via="drive_api", object_id=file_id, operation="object_changed" if changed else "object_snapshot",
                                    result="persisted" if changed else "unchanged", details={"logical_key": obj.logical_key, "version": str(after.get("version"))}))
        return records

    async def recover(self, ctx, scenario):
        ref = ctx.connection("operator")
        email = await self.account(ctx, ref)
        records = []
        keys = [key for key, spec in scenario.objects.items() if spec.driver == self.name]
        for group, control_name in [("baseline", None), ("test", None), *[("control", c.name) for c in scenario.controls]]:
            for key in [*keys, "folder"]:
                marker = object_marker(ctx.run_id, group, key, control_name)
                for data in await self.files(ctx, ref, marker):
                    obj = self.record(ctx, key, data, ref, email, marker, group, control_name)
                    previous = ctx.registry.records.get(ctx.registry.key(obj))
                    if email not in {o.get("emailAddress", "").lower() for o in data.get("owners", [])}:
                        obj.cleanup_status, obj.cleanup_detail = "retained", "Drive object owner changed"
                    elif previous:
                        obj.version = previous.version
                    elif data.get("createdTime") != data.get("modifiedTime"):
                        obj.cleanup_status, obj.cleanup_detail = "retained", "original version is unknown and object was modified"
                    records.append(obj)
        return records

    async def cleanup(self, ctx, obj):
        ctx.authorize("gdrive.delete_own")
        if obj.cleanup_status == "retained":
            return CleanupResult(status="retained", detail=obj.cleanup_detail)
        role = next((r for r, connection in ctx.connections.items() if connection == obj.connection_id), None)
        if role is None:
            return CleanupResult(status="retained", detail="connection is not owned by this run")
        ref = ctx.connection(role)
        email = await self.account(ctx, ref)
        data = await self.metadata(ctx, ref, obj.external_id)
        if data.get("trashed"):
            return CleanupResult(status="deleted", detail="already trashed")
        if data.get("appProperties", {}).get("argus_marker") != obj.marker:
            return CleanupResult(status="retained", detail="Drive marker changed")
        if owner_hash(email) != obj.owner or email not in {o.get("emailAddress", "").lower() for o in data.get("owners", [])}:
            return CleanupResult(status="retained", detail="Drive owner changed")
        if obj.version is None or str(data.get("version")) != obj.version:
            return CleanupResult(status="retained", detail="Drive version changed or original version is unknown")
        if data.get("mimeType") == "application/vnd.google-apps.folder":
            children = await self.pages(ctx, ref, {DRIVE_FILE}, BASE + "/files", "files", {"q": "trashed = false and '" + obj.external_id + "' in parents", "fields": "nextPageToken,files(id)", "pageSize": 100})
            if children:
                return CleanupResult(status="retained", detail="folder contains objects that were not safely cleaned")
        await self.request(ctx, ref, {DRIVE_FILE}, "PATCH", BASE + "/files/" + obj.external_id, json={"trashed": True})
        return CleanupResult(status="deleted", detail="owned Drive object moved to trash")
