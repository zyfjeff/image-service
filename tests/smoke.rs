use mktemp::Temp;
use std::io::Result;

mod builder;

#[test]
fn run() -> Result<()> {
    let work_dir = Temp::new_dir()?;

    let mut builder = builder::new(&work_dir);

    // create & build parent rootfs
    builder.make_parent()?;
    builder.build_parent()?;
    builder.check_bootstrap()?;

    // create & build source rootfs based parent
    builder.make_source()?;
    builder.build_source()?;

    Ok(())
}
