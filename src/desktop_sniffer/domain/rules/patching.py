def deep_diff(original, edited):
    if type(original) != type(edited):
        return edited
    if isinstance(original, dict):
        diff = {}
        for k in edited:
            if k not in original:
                diff[k] = edited[k]
            else:
                d = deep_diff(original[k], edited[k])
                if d is not None:
                    diff[k] = d
        for k in original:
            if k not in edited:
                diff[k] = "__SNARE_DELETE_FIELD__"
        return diff if diff else None
    elif isinstance(original, list):
        return edited if original != edited else None
    else:
        return edited if original != edited else None

def apply_patch(obj, patch):
    if isinstance(patch, dict) and isinstance(obj, dict):
        result = obj.copy()
        for k, v in patch.items():
            if v == "__SNARE_DELETE_FIELD__":
                result.pop(k, None)
            else:
                if k in result:
                    result[k] = apply_patch(result[k], v)
                else:
                    result[k] = v
        return result
    else:
        return patch

