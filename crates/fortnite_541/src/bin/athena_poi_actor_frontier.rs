//! Original UE4.21 source-only structural actor census for Athena's last
//! three HLOD-only POI worlds. Never exports cooked asset bytes or substitutes
//! any missing native StaticMesh. Private Rust-test is never fetched here.
use fortnite_541_importer::{properties,uobject};
use std::{collections::BTreeMap,env,fs,path::PathBuf,process::ExitCode};

const WORLDS:[(&str,&str);3]=[
    ("REC","Athena_POI_REC_001"),
    ("Warehouses","Athena_POI_Warehouses_003"),
    ("Pueblo","Athena_POI_Pueblo_001"),
];
// Exact original LF_7x12_GenericPlot / BuildingFoundation AdditionalWorlds
// FSoftObjectPath identities, retrieved from the authenticated source
// UMaps. Do not use these as a substitute for the actual cooked UWorlds.
const NESTED_WORLDS:[(&str,&str);20]=[
    ("REC01","Athena/Maps/Buildings/7x12/Athena_POI_GenericPlot_REC_001"),
    ("REC02","Athena/Maps/Buildings/7x12/Athena_POI_GenericPlot_REC_002"),
    ("REC03","Athena/Maps/Buildings/7x12/Athena_POI_GenericPlot_REC_003"),
    ("IND02","Athena/Maps/Buildings/7x12/Athena_POI_GenericPlot_IND_002"),
    ("IND03","Athena/Maps/Buildings/7x12/Athena_POI_GenericPlot_IND_003"),
    ("DCE01","Athena/Maps/Buildings/7x12/Athena_POI_GenericPlot_DCE_001"),
    ("P3a","Athena/Maps/Buildings/3x3/Athena_ARID_3x3_Pueblo_a"),
    ("P3b","Athena/Maps/Buildings/3x3/Athena_ARID_3x3_Pueblo_b"),
    ("P3c","Athena/Maps/Buildings/3x3/Athena_ARID_3x3_Pueblo_c"),
    ("P5a","Athena/Maps/Buildings/5x5/Athena_ARID_5x5_Pueblo_a"),
    ("P5b","Athena/Maps/Buildings/5x5/Athena_ARID_5x5_Pueblo_b"),
    ("P5c","Athena/Maps/Buildings/5x5/Athena_ARID_5x5_Pueblo_c"),
    ("P5d","Athena/Maps/Buildings/5x5/Athena_ARID_5x5_Pueblo_d"),
    ("GAS","Athena/Maps/Buildings/5x5/Athena_SUB_5x5_GasStation_b"),
    ("POOL","Athena/Maps/Buildings/5x5/Athena_URB_5x5_Pool_a"),
    ("PARK","Athena/Maps/Buildings/5x5/Athena_SUB_5x5_Park_c"),
    ("WHOUSEH","Athena/Maps/Buildings/3x3/Athena_IND_3x3_Warehouse_h"),
    ("FACTORY","Athena/Maps/Buildings/5x5/Athena_IND_5x5_Factory_g"),
    ("WHOUSEA","Athena/Maps/Buildings/3x3/Athena_IND_3x3_Warehouse_a"),
    ("SUBSTATION","Athena/Maps/Buildings/5x5/Athena_IND_5x5_SubStation_b"),
];
#[derive(Clone,Copy,Debug,Default)]
struct Counts{direct:usize,inherited:usize,scene_root:usize,other:usize,proxies:usize}
fn object_ref(fields:&properties::Properties,raw:&[u8],key:&str)
    ->Result<Option<i32>,String>{
    let mut found=fields.fields.iter().filter(|p|p.name==key);
    let Some(p)=found.next() else{return Ok(None)};
    if found.next().is_some()||p.kind!="ObjectProperty"||p.payload.len()!=4{
        return Err(format!("{key} source object reference malformed"));
    }
    let bytes=raw.get(p.payload.clone()).ok_or("object ref outside source export")?;
    Ok(Some(i32::from_le_bytes(bytes.try_into().unwrap())))
}
/// Parse exact UE4 FSoftObjectPath array bytes from original actor tags.
/// The pair of FNames belongs to the authentic source NameMap; no inferred
/// world names or generated POI location IDs are ever accepted.
fn authored_additional_worlds(
    cat:&uobject::PackageCatalog,props:&properties::Properties,raw:&[u8],
)->Result<Vec<String>,String>{
    let Some(field)=props.fields.iter().find(|p|p.name=="AdditionalWorlds")
        else{return Ok(Vec::new());};
    if field.kind!="ArrayProperty"{
        return Err("source POI AdditionalWorlds not an ArrayProperty".into());
    }
    let b=raw.get(field.payload.clone()).ok_or("source POI world array invalid")?;
    if b.len()<4{return Err("source POI world array count missing".into());}
    let n=u32::from_le_bytes(b[..4].try_into().unwrap()) as usize;
    if n>32||b.len()!=4+n*12{
        return Err("source POI FSoftObjectPath elements exceed exact original array".into());
    }
    let mut result=Vec::new();
    for i in 0..n{
        let pos=4+i*12;
        let id=u32::from_le_bytes(b[pos..pos+4].try_into().unwrap()) as usize;
        let number=u32::from_le_bytes(b[pos+4..pos+8].try_into().unwrap());
        let sub=i32::from_le_bytes(b[pos+8..pos+12].try_into().unwrap());
        if number!=0||sub!=0{return Err("source POI numbered/subobject world edge unsupported".into());}
        let name=cat.names.get(id).ok_or("source AdditionalWorlds FName outside NameMap")?;
        if !name.starts_with("/Game/"){return Err("source POI nested world not under /Game".into());}
        result.push(name.clone());
    }
    Ok(result)
}
fn audit_foundation(
    cat:&uobject::PackageCatalog,h:&[u8],x:&[u8],
    short:&str,actor_name:&str,actor_class:&str,
    props:&properties::Properties,raw:&[u8],
)->Result<(),String>{
    if !matches!(actor_class,
        "/Game/Athena/Environments/Blueprints/LF_7x12_GenericPlot::LF_7x12_GenericPlot_C"|
        "/Script/FortniteGame::BuildingFoundation3x3"|
        "/Script/FortniteGame::BuildingFoundation5x5"){return Ok(());}
    let list=props.fields.iter().map(|f|format!("{}:{}",f.name,f.kind)).collect::<Vec<_>>();
    let world_edges=authored_additional_worlds(cat,props,raw)?;
    let mut authored_children=Vec::new();
    for (i,c) in cat.exports.iter().enumerate(){
        if cat.source_object_path((i+1) as i32).ok().is_some_and(|id|
            id.starts_with(&format!("{actor_name}::"))) {
            let kind=cat.export_class_name(c).unwrap_or("");
            if kind.ends_with("Component"){
                let data=cat.export_data(h,x,c)?;
                let fields=properties::scan(cat,data)?;
                let mesh=object_ref(&fields,data,"StaticMesh")?
                    .filter(|id|*id!=0)
                    .map(|id|cat.source_object_path(id))
                    .transpose()?;
                authored_children.push(format!("{kind}::{mesh:?}"));
            }
        }
    }
    println!("ORIGINAL_541_FOUNDATION_SOURCE_CONTRACT {short} class={actor_class} actor={actor_name} tagged_fields={list:?} direct_additional_worlds={world_edges:?} owned_child_components={authored_children:?}");
    Ok(())
}

fn root_mesh_kind(kind:&str,game_blueprint:bool)->&'static str{
    match kind{
        "StaticMeshComponent"=>"static",
        _ if game_blueprint&&kind.ends_with("Component")=>"blueprint-scene",
        _=>"other",
    }
}
fn inspect(root:&PathBuf,name:&str,short:&str)->Result<(),String>{
    let path=if name.starts_with("Athena/Maps/Buildings/"){
        root.join("FortniteGame/Content").join(name)
    }else{
        root.join("FortniteGame/Content/Athena/Maps/POI").join(name)
    };
    let is_nested=name.starts_with("Athena/Maps/Buildings/");
    let h=fs::read(path.with_extension("umap"))
        .map_err(|e|format!("original {name}.umap missing: {e}"))?;
    let x=fs::read(path.with_extension("uexp"))
        .map_err(|e|format!("original {name}.uexp missing: {e}"))?;
    let cat=uobject::inspect(&h)?;
    let mut totals=Counts::default();
    let mut missing_classes=BTreeMap::<String,usize>::new();
    let mut scene_root_classes=BTreeMap::<String,usize>::new();
    for (i,actor) in cat.exports.iter().enumerate(){
        let kind=cat.export_class_name(actor).unwrap_or("");
        if kind=="LODActor"||kind=="FortHLODSMActor"{
            totals.proxies+=1;
            continue;
        }
        if kind.ends_with("Component")||kind=="World"||kind=="Level"{continue;}
        let raw=cat.export_data(&h,&x,actor)?;
        let props=match properties::scan(&cat,raw){Ok(p)=>p,Err(_)=>continue};
        let Some(root_ref)=object_ref(&props,raw,"RootComponent")?else{continue};
        if root_ref<=0{continue;}
        let Some(component)=cat.exports.get((root_ref-1) as usize)else{continue};
        if component.outer_index!=(i+1) as i32{continue;}
        let actor_class=cat.source_object_path(actor.class_index)?;
        let actor_name=cat.source_object_path((i+1) as i32)?;
        audit_foundation(&cat,&h,&x,short,&actor_name,&actor_class,&props,raw)?;
        let game_blueprint=actor_class.starts_with("/Game/")&&
            actor_class.rsplit_once("::").is_some_and(|(_,name)|name.ends_with("_C"));
        let comp_kind=cat.export_class_name(component).unwrap_or("");
        match root_mesh_kind(comp_kind,game_blueprint){
            "static"=>{
                let raw_comp=cat.export_data(&h,&x,component)?;
                let props_comp=properties::scan(&cat,raw_comp)?;
                match object_ref(&props_comp,raw_comp,"StaticMesh")?{
                    Some(mesh_ref) if mesh_ref!=0=>{
                        let original=cat.source_object_path(mesh_ref)?;
                        totals.direct+=1;
                        if !is_nested{
                            println!("ORIGINAL_541_POI_ACTOR_SOURCE {short} class={actor_class} actor={actor_name} kind=direct_mesh source={original}");
                        }
                    },
                    _=>{
                        totals.inherited+=1;
                        *missing_classes.entry(actor_class.clone()).or_default()+=1;
                        if !is_nested{
                            println!("ORIGINAL_541_POI_ACTOR_SOURCE {short} class={actor_class} actor={actor_name} kind=inherited_missing_local_mesh component_class={comp_kind}");
                        }
                    },
                }
            },
            "blueprint-scene"=>{
                totals.scene_root+=1;
                *scene_root_classes.entry(actor_class.clone()).or_default()+=1;
                if !is_nested{
                    println!("ORIGINAL_541_POI_ACTOR_SOURCE {short} class={actor_class} actor={actor_name} kind=blueprint_scene_root component_class={comp_kind}");
                }
            },
            _=>totals.other+=1,
        }
    }
    println!("ORIGINAL_541_POI_CLASS_FRONTIER {short} original_world={name} direct_static_mesh_placements={} inherited_mesh_placements={} scene_root_blueprint_placements={} known_hlod_proxy_actors={} other_scene_roots={} inherited_classes={missing_classes:?} scene_root_classes={scene_root_classes:?}",
        totals.direct,totals.inherited,totals.scene_root,totals.proxies,totals.other);
    Ok(())
}
fn run()->Result<(),String>{
    let root=PathBuf::from(env::args_os().nth(1).ok_or(
        "usage: athena_poi_actor_frontier VERIFIED_SOURCE_ROOT")?);
    for (short,name) in WORLDS{inspect(&root,name,short)?;}
    for (short,name) in NESTED_WORLDS{
        inspect(&root,name,short)?;
    }
    Ok(())
}
fn main()->ExitCode{
    match run(){Ok(())=>ExitCode::SUCCESS,Err(e)=>{
        eprintln!("ORIGINAL_541_POI_SOURCE_PROBE_FAILED: {e}");ExitCode::FAILURE
    }}
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn only_exact_native_static_components_count_as_direct_root(){
        assert_eq!(root_mesh_kind("StaticMeshComponent",false),"static");
        assert_eq!(root_mesh_kind("StaticMeshComponent",true),"static");
        assert_eq!(root_mesh_kind("SceneComponent",true),"blueprint-scene");
        assert_eq!(root_mesh_kind("PointLightComponent",false),"other");
        assert_eq!(root_mesh_kind("SceneComponent",false),"other");
    }
    #[test]fn absent_root_object_property_does_not_invent_a_mesh(){
        let props=properties::Properties{fields:Vec::new(),bytes_consumed:0};
        assert_eq!(object_ref(&props,&[],"StaticMesh").unwrap(),None);
    }
}
