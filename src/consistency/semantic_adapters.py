"""Bounded public-log adapters. No code execution, SQL keyword labeling or GT inference."""
from consistency.semantic_model import new_action, slot, validate_action


def resource(kind, namespace, key, ref):
    return slot({"kind": kind, "namespace": namespace, "key": key}, type="resource", refs=[ref])


def adapt_tool_call(aid, name, arguments, *, run, source_ref):
    """Only explicit argument shapes are mapped. Tool versions remain unknown.

    SQL retains exact submitted text; browser target refs retain unknown snapshot
    scope. create_or_update, arbitrary scripts and business APIs are not guessed.
    """
    profiles = {"read_text_file": ("file.read@1", "read"), "read_file": ("file.read@1", "read"),
                "write_file": ("file.write@1", "unknown"), "move_file": ("file.move@1", "transfer"),
                "execute_sql": ("database.statement@1", "execute")}
    profile, operation = profiles.get(name, ("unsupported", "unknown"))
    if name.startswith("browser_"):
        profile, operation = "browser.event@1", "control"
    action = new_action(aid, profile, operation=operation, run=run)
    action["pathway"]["interface"] = "mcp"
    action["pathway"]["actuator"] = ("filesystem" if profile.startswith("file.") else
        "database" if profile == "database.statement@1" else "browser" if profile == "browser.event@1" else "unknown")
    action["fields"]["tool_name"] = slot(name, refs=[source_ref])
    action["fields"]["tool_version"] = slot(status="unknown", reason="historical_tool_declaration_missing")
    action["fields"]["raw_arguments"] = slot(arguments, type="json", refs=[source_ref])
    fields = action["fields"]
    args = arguments if isinstance(arguments, dict) else {}
    mappings = {
        "file.read@1": (("path", "source"),),
        "file.write@1": (("path", "target"),),
        "file.move@1": (("source", "source"), ("destination", "target")),
    }
    for original, target in mappings.get(profile, ()):
        if isinstance(args.get(original), str) and args[original]:
            fields[target] = resource("file", run + ":filesystem", args[original], source_ref)
    if profile == "file.write@1" and isinstance(args.get("content"), str):
        fields["content"] = slot(args["content"], refs=[source_ref])
    if profile == "database.statement@1":
        action["structure"] = "opaque"  # do not split SQL on semicolons/keywords
        if isinstance(args.get("sql"), str):
            fields["statement"] = slot(args["sql"], refs=[source_ref])
    if profile == "browser.event@1":
        fields["event"] = slot(name, refs=[source_ref])
        if isinstance(args.get("ref"), str):
            fields["target"] = slot(args["ref"], refs=[source_ref])
        if "text" in args:
            fields["value"] = slot(args["text"], type="json", refs=[source_ref])
        # ref without snapshot/frame/origin cannot become a globally unique DOM ID.
    return validate_action(action)


def adapt_api_request(aid, request, *, run, source_ref):
    """A method/url/data row establishes neither a response nor a business effect."""
    action = new_action(aid, "unsupported", run=run)
    action["pathway"]["interface"] = "direct_api"
    action["pathway"]["actuator"] = "application_api"
    action["fields"] = {"raw_request": slot(request, type="json", refs=[source_ref]),
                        "semantic_support": slot(status="unsupported", reason="requires_same_run_endpoint_semantics_and_code_binding"),
                        "result_value": slot(type="json", status="unknown", reason="request_log_is_not_response_evidence")}
    return validate_action(action)
