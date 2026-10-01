from gcp_goat.output import safe_text


def test_safe_text_removes_terminal_escape_sequences():
    assert safe_text("normal\x1b[31mred\x00") == "normal[31mred"


def test_safe_text_can_preserve_newlines_for_message_bodies():
    assert safe_text("line one\nline two", multiline=True) == "line one\nline two"
    assert safe_text("line one\nline two") == "line oneline two"
