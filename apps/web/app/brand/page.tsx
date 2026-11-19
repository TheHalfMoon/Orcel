import type { Metadata } from "next";
import "./brand.css";

export const metadata: Metadata = {
  title: "Orcel Identity v5",
  description: "The Orcel identity: People first. A vermilion figure, a black lowercase name, and one person directing many agents.",
};

const basePath=process.env.ORCEL_WEB_BASE_PATH??"";
const asset=(file:string)=>basePath+"/brand/"+file;
const kit=asset("Orcel-Identity-Kit-v5.zip");
const palette=[
 {name:"Vermilion",hex:"#DB2532"},{name:"Ink",hex:"#141414"},
 {name:"Deep Navy",hex:"#182437"},{name:"Cobalt",hex:"#2354D4"},
 {name:"Orange",hex:"#F5724D"},{name:"Sky",hex:"#BFD8F7"},{name:"Ivory",hex:"#F7F3EB"}
];
const icons=[
 {label:"Orcel",image:"orcel-app-icon.svg",alt:"Vermilion figure on an ivory application tile",detail:"Desktop, favicon, ChatGPT and Codex"},
 {label:"Orcel Browser",image:"orcel-icon-browser.svg",alt:"Ink figure on an orange disc inside an ink ring",detail:"Browse with an agent"},
 {label:"Orcel Agent",image:"orcel-icon-agent.svg",alt:"One person connected to two agents",detail:"One person, many agents"},
 {label:"Orcel MCP",image:"orcel-icon-mcp.svg",alt:"Ivory connection hub on a navy tile",detail:"Connect your tools"},
 {label:"Orcel Cluster",image:"orcel-icon-cluster.svg",alt:"Four red dots joined in a ring on a sky tile",detail:"Many machines"}
];
export default function BrandPage(){
 return <main className="orcel-brand-system">
   <div className="brand-shell">
    <header className="brand-nav">
     <a href={basePath+"/"} aria-label="Return to Orcel homepage">orcel</a>
     <span>PEOPLE FIRST / 2026</span>
     <a href={kit}>Download kit ↗</a>
    </header>
    <section className="brand-intro">
     <div className="brand-eyebrow">OFFICIAL VISUAL IDENTITY</div>
     <h1>People first.</h1>
     <p>One person. Many agents. A vermilion figure, a black lowercase name, and agents that
     act on your computer only with your yes.</p>
    </section>
    <section className="brand-hero" aria-label="Primary Orcel logo">
      <div className="brand-main-lockup">
       <img src={asset("orcel-lockup-black.svg")} width="1350" height="384"
         alt="Orcel primary logo: vermilion figure and black lowercase orcel wordmark"/>
      </div>
      <div className="brand-hero-caption">
       <span>01 / PRIMARY LOGO</span><strong>orcel</strong><span>Vermilion / Ink / Ivory</span>
      </div>
    </section>
    <div className="brand-heading">
      <h2>One figure. Five products.</h2>
      <p>Every icon is generated from a single editable vector source.</p>
    </div>
    <section className="brand-tiles" aria-label="Orcel product icons">
      {icons.map((icon)=><article key={icon.image} className="brand-tile">
       <p>{icon.label}</p>
       <img src={asset(icon.image)} width={160} height={160} alt={icon.alt}/>
       <span>{icon.detail}</span>
      </article>)}
    </section>
    <section className="brand-palette" aria-labelledby="color-title">
      <div className="brand-heading">
       <h2 id="color-title">Vermilion, ink, cobalt.</h2>
       <p>Vermilion for the figure and the one thing that needs you; ink for the name; ivory for the page.</p>
      </div>
      <div className="brand-swatches">
       {palette.map(p=><div className="brand-swatch" key={p.hex}>
        <span className="brand-swatch-color" style={{backgroundColor:p.hex}}/>
        <strong>{p.name}</strong><code>{p.hex}</code>
       </div>)}
      </div>
    </section>
    <section className="brand-principle">
      <span>A CONSISTENT VISUAL LANGUAGE</span>
      <h2>A person, then a name.<br/>Clear at 16px.</h2>
      <p>The figure is as tall as the l of orcel. Keep half its height clear on every side. Never
      retype the wordmark; no shadows, gradients or effects on any mark.</p>
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
