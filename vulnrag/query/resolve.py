import difflib


def resolve_component(component: str | None, products: set[str],
                      cutoff: float = 0.85) -> str | None:
    """Snap a (possibly misspelled) component to the closest known product name.
    Exact match or no component -> returned unchanged. If nothing is close
    enough, returned unchanged (so unknown components still yield not_found)."""
    if not component or component in products:
        return component
    matches = difflib.get_close_matches(component, list(products), n=1, cutoff=cutoff)
    return matches[0] if matches else component
