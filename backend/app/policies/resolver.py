from sqlalchemy import select
from app.models import PolicyOverride, GroupMember
from app.policies.schema import merge_layers


class PolicyConflict(ValueError):
    pass


def applicable_layers(db, policy_id, device):
    """Layers that apply to one computer, lowest precedence first: global, class, group, then computer."""
    groups = set(db.scalars(select(GroupMember.group_id).where(GroupMember.device_id == device.id)))
    layers = []
    for layer in db.scalars(select(PolicyOverride).where(PolicyOverride.policy_id == policy_id)):
        applies = (layer.scope == "GLOBAL" or layer.scope == "CLASS" and layer.device_class == device.device_class
                   or layer.scope == "GROUP" and layer.group_id in groups or layer.scope == "DEVICE" and layer.device_id == device.id)
        if applies:
            layers.append({"id": layer.id, "priority": layer.priority, "controls": layer.controls, "scope": layer.scope,
                           "target": layer.device_id or layer.group_id or layer.device_class, "reason": layer.reason,
                           "approved_relaxation": layer.approved_relaxation})
    return sorted(layers, key=lambda x: (x["priority"], x["id"]))


def resolve(db, policy_id, baseline, device):
    layers = applicable_layers(db, policy_id, device)
    resolutions = {key for l in layers if l["priority"] == 30 for key in l["controls"]}
    grouped = {}
    for layer in layers:
        if layer["priority"] == 20:
            for key, value in layer["controls"].items():
                if key in grouped and grouped[key] != value and key not in resolutions:
                    raise PolicyConflict("policy.group_conflict:" + key)
                grouped[key] = value
    return merge_layers(baseline, layers)
