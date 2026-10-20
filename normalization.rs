use percent_encoding::percent_decode;

fn decoder(input: String) -> String {
    let mut current = input;
    // shortcut: 10 decode passes, raise if a bypass needs deeper encoding
    for _ in 0..10 {
        let decoded = percent_decode(current.as_bytes())
            .decode_utf8_lossy()
            .to_string();
        if decoded == current {
            break;
        }

        current = decoded;
    }

    current
}

#[allow(dead_code)]
pub fn normalize(path: String) -> String {
    let mut decoded = decoder(path);
    decoded = decoded.to_lowercase();
    decoded = decoded.trim().to_string();
    decoded = decoded.replace('\0', "");
    decoded = decoded.replace("/*", "");
    decoded = decoded.replace("*/", "");
    while decoded.contains("//") || decoded.contains("..\\") {
        decoded = decoded.replace("//", "/");
        decoded = decoded.replace("..\\", "../");
    }
    decoded
}

#[cfg(test)]
mod tests {
    use super::normalize;

    #[test]
    fn double_encoded_traversal_reduces_to_dot_dot_slash() {
        assert_eq!(normalize("%252e%252e%252f".into()), "../");
    }

    #[test]
    fn deeply_encoded_percent_stops_at_the_cap() {
        // 12 levels of %-encoding; the cap is 10 passes, so 2 levels remain
        assert_eq!(normalize(format!("%25{}", "25".repeat(11))), "%2525");
    }

    #[test]
    fn sql_comment_and_case_are_stripped() {
        assert_eq!(normalize("UnIoN/**/SeLeCt".into()), "unionselect");
    }

    #[test]
    fn double_slashes_collapse() {
        assert_eq!(normalize("/etc//passwd".into()), "/etc/passwd");
    }

    #[test]
    fn backslash_traversal_becomes_forward_slash() {
        assert_eq!(normalize("..\\windows".into()), "../windows");
    }

    #[test]
    fn null_bytes_are_removed() {
        assert_eq!(normalize("/etc/passwd\0".into()), "/etc/passwd");
    }

    #[test]
    fn benign_path_is_unchanged() {
        assert_eq!(normalize("/index.html".into()), "/index.html");
    }
}
