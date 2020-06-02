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
    let build_ret = builder.build_parent()?;

    let nydusd = nydusd::new(&work_dir)?;
    nydusd.start()?;

    let mount_ret = builder.mount_check()?;

    println!("build result: {}", build_ret);
    println!("mount result: {}", mount_ret);

    assert_eq!(build_ret, mount_ret);

    // create & build source rootfs based parent
    builder.make_source()?;
    builder.build_source()?;

    Ok(())
}
