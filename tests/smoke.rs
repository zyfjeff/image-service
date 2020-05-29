use mktemp::Temp;
use std::io::Result;

mod builder;
mod nydusd;

#[test]
fn run() -> Result<()> {
    let work_dir = Temp::new_dir()?;

    let mut builder = builder::new(&work_dir);

    // create & build parent rootfs
    builder.make_parent()?;
    builder.build_parent()?;

    let nydusd = nydusd::new(&work_dir)?;
    nydusd.start()?;

    builder.check()?;

    // create & build source rootfs based parent
    builder.make_source()?;
    builder.build_source()?;

    Ok(())
}
