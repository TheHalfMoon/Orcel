import type { Metadata } from "next";
import "./brand.css";

export const metadata: Metadata = {
  title: "Orcel Identity v4",
  description: "The Orcel identity: a desktop window holding Halfmoon's half moon, in the Halfmoon palette and type.",
};

const basePath=process.env.ORCEL_WEB_BASE_PATH??"";
const asset=(file:string)=>basePath+"/brand/"+file;
const kit=asset("Orcel-Identity-Kit-v4.zip");
const neutrals=[
 {name:"Midnight",hex:"#090C12"},{name:"White",hex:"#FFFFFF"},
 {name:"Lunar",hex:"#F5F4F0"},{name:"Lavender",hex:"#A6ACE6"},
 {name:"Mist",hex:"#F5F6F7"},{name:"Graphite",hex:"#565D66"}
];
const variants=[
 {label:"02 / Dark application",image:"orcel-app-icon.svg",alt:"White Moon Tile with a lavender moon on a midnight application tile",light:false,detail:"ChatGPT, Codex and app"},
 {label:"03 / Light application",image:"orcel-app-icon-light.svg",alt:"Midnight Moon Tile on a lunar application tile",light:true,detail:"Light UI and print"},
 {label:"04 / Horizontal lockup",image:"orcel-lockup-white.svg",alt:"Orcel Night Window mark and white wordmark",light:false,detail:"Website, presentations and headers",wide:true},
 {label:"05 / Inverse lockup",image:"orcel-lockup-black.svg",alt:"Orcel Night Window mark and midnight wordmark",light:true,detail:"Docs and light surfaces",wide:true},
 {label:"06 / Stacked lockup",image:"orcel-lockup-stacked-white.svg",alt:"Orcel stacked Night Window mark and wordmark",light:false,detail:"Square promotional layouts"},
 {label:"07 / Accent tile",image:"orcel-accent-icon.svg",alt:"Midnight Night Window mark on a lavender tile",light:false,detail:"Avatars and moments of action"}
];
export default function BrandPage(){
 return <main className="orcel-brand-system">
   <div className="brand-shell">
    <header className="brand-nav">
     <a href={basePath+"/"} aria-label="Return to Orcel homepage">orcel</a>
     <span>A HALFMOON PRODUCT / 2026</span>
     <a href={kit}>Download kit ↗</a>
    </header>
    <section className="brand-intro">
     <div className="brand-eyebrow">OFFICIAL VISUAL IDENTITY</div>
     <h1>The Night Window.</h1>
     <p>Your computer is the window. The half moon inside comes from Halfmoon's own shapes:
     what you choose to let through, and nothing more.</p>
    </section>
    <section className="brand-hero" aria-label="Primary Orcel logo">
      <div className="brand-main-lockup">
       <img src={asset("orcel-lockup-white.svg")} width="940" height="256"
         alt="Orcel primary horizontal logo: white Night Window mark and wordmark"/>
      </div>
      <div className="brand-hero-caption">
       <span>01 / PRIMARY LOGO</span><strong>orcel</strong><span>White / Midnight / Lavender</span>
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
         width={variant.wide?425:210} height={variant.wide?116:210} alt={variant.alt}/>
       <span>{variant.detail}</span>
      </article>)}
    </section>
    <section className="brand-palette" aria-labelledby="color-title">
      <div className="brand-heading">
       <h2 id="color-title">Made of essentials.</h2>
       <p>Halfmoon's palette: Midnight and white, Lunar for reading, Lavender for the moon, Red only to stop.</p>
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
      <p>Keep one moon-width clear on every side. The crescent belongs to Halfmoon alone; Orcel uses
      it only in the line "a Halfmoon product". No shadows, gradients, or extra cuts.</p>
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
