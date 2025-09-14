def parse_banner(banner_text: str) -> str:
    if not banner_text:
        return ''
    return ' '.join(banner_text.split())