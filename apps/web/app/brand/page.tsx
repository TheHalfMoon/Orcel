import type { Metadata } from "next";
import "./brand.css";

export const metadata: Metadata = {
  title: "Orcel Orca Eye Identity",
  description: "The Orcel Orca Eye identity: a circle with an orca eye patch, an Unbounded wordmark, and Signal Lime for action.",
};

const basePath=process.env.ORCEL_WEB_BASE_PATH??"";
const asset=(file:string)=>basePath+"/brand/"+file;
const kit=asset("Orcel-Identity-Kit-v3.zip");
const neutrals=[
 {name:"White",hex:"#FFFFFF"},{name:"Ink",hex:"#080808"},
 {name:"Charcoal",hex:"#17191B"},{name:"Signal Lime",hex:"#D4FF3F"},
 {name:"Mist",hex:"#F5F6F7"},{name:"Graphite",hex:"#565D66"}
];
const variants=[
 {label:"02 / Dark application",image:"orcel-app-icon.svg",alt:"White Orca Eye mark on black application tile",light:false,detail:"ChatGPT, Codex and app"},
 {label:"03 / Light application",image:"orcel-app-icon-light.svg",alt:"Black Orca Eye mark on pale application tile",light:true,detail:"Light UI and print"},
 {label:"04 / Horizontal lockup",image:"orcel-lockup-white.svg",alt:"Orcel Orca Eye mark and white wordmark",light:false,detail:"Website, presentations and headers",wide:true},
 {label:"05 / Inverse lockup",image:"orcel-lockup-black.svg",alt:"Orcel Orca Eye mark and black wordmark",light:true,detail:"Docs and light surfaces",wide:true},
 {label:"06 / Stacked lockup",image:"orcel-lockup-stacked-white.svg",alt:"Orcel Orca Eye stacked mark and wordmark",light:false,detail:"Square promotional layouts"},
 {label:"07 / Accent tile",image:"orcel-accent-icon.svg",alt:"Black Orca Eye mark on a Signal Lime tile",light:false,detail:"Avatars and moments of action"}
];
export default function BrandPage(){
 return <main className="orcel-brand-system">
   <div className="brand-shell">
    <header className="brand-nav">
     <a href={basePath+"/"} aria-label="Return to Orcel homepage">orcel</a>
     <span>ORCA EYE / 2026</span>
     <a href={kit}>Download kit ↗</a>
    </header>
    <section className="brand-intro">
     <div className="brand-eyebrow">OFFICIAL VISUAL IDENTITY</div>
     <h1>The Orca Eye.</h1>
     <p>One circle and one eye patch. Orcel sounds like orca: black and white, calm, and watchful.
     The mark stays mono; Signal Lime is saved for action.</p>
    </section>
    <section className="brand-hero" aria-label="Primary Orcel logo">
      <div className="brand-main-lockup">
       <img src={asset("orcel-lockup-white.svg")} width="1100" height="256"
         alt="Orcel primary horizontal logo: white Orca Eye mark and wordmark"/>
      </div>
      <div className="brand-hero-caption">
       <span>01 / PRIMARY LOGO</span><strong>orcel</strong><span>White / Ink / Lime</span>
      </div>
    </section>
    <div className="brand-heading">
      <h2>One system. Every surface.</h2>
      <p>Artwork is generated from a single editable vector source.</p>
    </div>
    <section className="brand-tiles" aria-label="Orcel identity variants">
      {variants.map((variant)=><article key={variant.image} className={"brand-tile "+(variant.light?"light":"dark")}>
       <p>{variant.label}</p>
       <img className={variant.wide?"brand-wide":""} src={asset(variant.image)}
         width={variant.wide?425:210} height={variant.wide?99:210} alt={variant.alt}/>
       <span>{variant.detail}</span>
      </article>)}
    </section>
    <section className="brand-palette" aria-labelledby="color-title">
      <div className="brand-heading">
       <h2 id="color-title">Made of essentials.</h2>
       <p>Black and white forms, one lime for action, and restrained neutral surfaces.</p>
      </div>
      <div className="brand-swatches">
       {neutrals.map(p=><div className="brand-swatch" key={p.hex}>
        <span className="brand-swatch-color" style={{backgroundColor:p.hex}}/>
        <strong>{p.name}</strong><code>{p.hex}</code>
       </div>)}
      </div>
    </section>
    <section className="brand-principle">
      <span>A CONSISTENT VISUAL LANGUAGE</span>
      <h2>Simple at 16px.<br/>Distinctive at every scale.</h2>
      <p>Keep the mark to one circle and one patch, always a single color, with a quarter of its
      width clear on every side. No shadows, outlines, gradients, or lime inside the mark.</p>
      <a className="brand-download" href={kit}>Download complete Orcel identity kit ↗</a>
      <p><a href="https://github.com/TheHalfMoon/Orcel/blob/main/assets/brand/IDENTITY.md">Read the vector construction and usage guide ↗</a></p>
    </section>
    <footer className="brand-bottom">
      <a href={basePath+"/"}>orcel</a>
      <span>Your computer, your terms.</span>
      <a href="https://github.com/TheHalfMoon/Orcel">Open-source repository ↗</a>
    </footer>
   </div>
 </main>;
}
