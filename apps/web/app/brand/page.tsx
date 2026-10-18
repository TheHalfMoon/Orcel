import type { Metadata } from "next";
import "./brand.css";

export const metadata: Metadata = {
  title: "Orcel Signal Identity",
  description: "The Orcel Signal identity: custom lowercase typography with a deliberate o opening, continuous c, orange l and matching icon.",
};

const basePath=process.env.ORCEL_WEB_BASE_PATH??"";
const asset=(file:string)=>basePath+"/brand/"+file;
const kit=asset("Orcel-Identity-Kit-v2.zip");
const neutrals=[
 {name:"White",hex:"#FFFFFF"},{name:"Ink",hex:"#080808"},
 {name:"Charcoal",hex:"#17191B"},{name:"Signal orange",hex:"#FF813E"},
 {name:"Mist",hex:"#F5F6F7"},{name:"Graphite",hex:"#565D66"}
];
const variants=[
 {label:"02 / Dark application",image:"orcel-app-icon.svg",alt:"White Signal icon with orange terminal on black application tile",light:false,detail:"ChatGPT, Codex and app"},
 {label:"03 / Light application",image:"orcel-app-icon-light.svg",alt:"Black Signal icon with orange terminal on pale application tile",light:true,detail:"Light UI and print"},
 {label:"04 / Horizontal lockup",image:"orcel-lockup-white.svg",alt:"Orcel Signal white-and-orange typographic wordmark",light:false,detail:"Website, presentations and headers",wide:true},
 {label:"05 / Inverse lockup",image:"orcel-lockup-black.svg",alt:"Orcel Signal black-and-orange typographic wordmark",light:true,detail:"Docs and light surfaces",wide:true},
 {label:"06 / Stacked lockup",image:"orcel-lockup-stacked-white.svg",alt:"Orcel Signal stacked symbol and wordmark",light:false,detail:"Square promotional layouts"},
 {label:"07 / Editorial accent",image:"orcel-accent-icon.svg",alt:"Orcel Signal orange terminal on charcoal",light:false,detail:"Alternate dark application treatment"}
];
export default function BrandPage(){
 return <main className="orcel-brand-system">
   <div className="brand-shell">
    <header className="brand-nav">
     <a href={basePath+"/"} aria-label="Return to Orcel homepage">orcel</a>
     <span>SIGNAL / 2026</span>
     <a href={kit}>Download kit ↗</a>
    </header>
    <section className="brand-intro">
     <div className="brand-eyebrow">OFFICIAL VISUAL IDENTITY</div>
     <h1>A clear signal.</h1>
     <p>An original typographic wordmark. Deliberate o opening and continuous c. A vivid orange terminal on l.
     Distinctive, intentional, and built for a clear, durable identity.</p>
    </section>
    <section className="brand-hero" aria-label="Primary Orcel Signal wordmark">
      <div className="brand-main-lockup">
       <img src={asset("orcel-lockup-white.svg")} width="900" height="256"
         alt="Orcel primary horizontal logo: white and orange Orcel Signal wordmark"/>
      </div>
      <div className="brand-hero-caption">
       <span>01 / PRIMARY SIGNAL WORDMARK</span><strong>orcel</strong><span>White / Orange / Ink</span>
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
         width={variant.wide?425:210} height={variant.wide?121:210} alt={variant.alt}/>
       <span>{variant.detail}</span>
      </article>)}
    </section>
    <section className="brand-palette" aria-labelledby="color-title">
      <div className="brand-heading">
       <h2 id="color-title">Made of essentials.</h2>
       <p>White forms, one orange signal, and restrained neutral surfaces.</p>
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
      <p>Preserve the deliberate o slit, continuous open-sided c, and orange tip on l,
      with the original lowercase vector wordmark. No shadows,
      extra artificial letter cuts, gradients, or unnecessary decoration.</p>
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
