use std::{fs, path::PathBuf};
use structopt::StructOpt;
use varsig::prelude::*;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "varsig-inspector",
    version = "0.1",
    author = "Dave Huseby <dwh@linuxprogrammer.org>",
    about = "Varsig Instpector"
)]
struct Opt {
    /// file to parse
    #[structopt(parse(from_os_str))]
    input: PathBuf,
}

fn main() -> Result<()> {
    let opt = Opt::from_args();

    let bytes = fs::read(opt.input)?;
    let vs = Varsig::try_from(bytes)?;

    println!("{}", vs);

    Ok(())
}

/*
fn print_ipld(key: Option<String>, ipld: &Ipld, ind: usize) {
    let indent = if ind > -1 {
        format!("{:ind$}", " ")
    } else {
        "".to_string()
    };

    let key = match key {
        Some(k) => format!("{}: ", k),
        None => "".to_string(),
    };

    match ipld {
        Ipld::Null => println!("{indent}{key}{}", "null"),
        Ipld::Bool(b) => println!("{indent}{key}{}", b),
        Ipld::Integer(i) => println!("{indent}{key}{}", i),
        Ipld::Float(f) => println!("{indent}{key}{}", f),
        Ipld::String(s) => println!("{indent}{key}{}", s),
        Ipld::Bytes(b) => println!("{indent}{key}{:?}", b),
        Ipld::List(l) => {
            println!("{indent}{key}[");
            for i in l {
                print_ipld(None, &i, ind + 4);
            }
            println!("{indent}]");
        }
        Ipld::Map(m) => {
            println!("{indent}{key}{{");
            for (k, v) in m.iter() {
                print_ipld(Some(k.clone()), &v, ind + 3);
            }
            println!("{indent}}}");
        }
        Ipld::Link(cid) => println!("{indent}{key}{}", cid),
    }
}
*/
