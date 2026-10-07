use std::io::{self, Read, Write};

pub const MAX_FRAME_SIZE: usize = 64 * 1024;

pub fn read_frame(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header)?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid protocol frame size",
        ));
    }
    let mut payload = vec![0; size];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

pub fn write_frame(writer: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    if payload.is_empty() || payload.len() > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid protocol frame size",
        ));
    }
    let size = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid protocol frame size"))?;
    writer.write_all(&size.to_be_bytes())?;
    writer.write_all(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn accepts_max_frame_and_rejects_oversized_before_payload_allocation() {
        let mut frame = Vec::from((MAX_FRAME_SIZE as u32).to_be_bytes());
        frame.extend(std::iter::repeat_n(0_u8, MAX_FRAME_SIZE));
        assert_eq!(
            read_frame(&mut Cursor::new(frame)).unwrap().len(),
            MAX_FRAME_SIZE
        );

        let mut oversized = Cursor::new(((MAX_FRAME_SIZE as u32) + 1).to_be_bytes());
        assert_eq!(
            read_frame(&mut oversized).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(oversized.position(), 4);
    }

    #[test]
    fn truncated_and_empty_frames_fail() {
        assert_eq!(
            read_frame(&mut Cursor::new([0, 0, 0])).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            read_frame(&mut Cursor::new([0, 0, 0, 0]))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            read_frame(&mut Cursor::new([0, 0, 0, 2, b'{']))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
