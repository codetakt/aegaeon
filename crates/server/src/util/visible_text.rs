pub(crate) fn is_visible_nfc_text(value: &str) -> bool {
    use icu_properties::{
        props::{BidiControl, DefaultIgnorableCodePoint},
        CodePointSetData,
    };
    !value.is_empty()
        && value.trim() == value
        && unicode_normalization::is_nfc(value)
        && value.chars().all(|c| {
            !c.is_control()
                && !CodePointSetData::new::<BidiControl>().contains(c)
                && !CodePointSetData::new::<DefaultIgnorableCodePoint>().contains(c)
        })
}
