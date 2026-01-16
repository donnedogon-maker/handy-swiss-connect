import { useEffect } from "react";
import { useLocation } from "react-router-dom";
import { useTranslation } from "react-i18next";

interface SEOConfig {
  title?: string;
  description?: string;
  keywords?: string;
  canonicalPath?: string;
  type?: string;
  image?: string;
}

const defaultConfig: SEOConfig = {
  title: "TipTop Service – Ihr Handwerker in Zürich & Schweiz | 24h Notdienst",
  description: "★ Zuverlässiger Handyman in Zürich: Reparaturen, Renovierung, Elektrik, Sanitär, Malerarbeiten. Faire Preise ✓ Schnelle Termine ✓ 24h Notdienst ✓ ☎ +41 79 813 51 47",
  keywords: "handwerker zürich, handyman schweiz, renovierung, malerarbeiten, elektrik, sanitär, 24h notdienst",
  type: "website",
  image: "https://tiptop-service.ch/og-image.jpg"
};

const pageConfigs: Record<string, SEOConfig> = {
  "/": {
    title: "TipTop Service – Ihr Handwerker in Zürich & Schweiz | 24h Notdienst",
    description: "★ Zuverlässiger Handyman in Zürich: Reparaturen, Renovierung, Elektrik, Sanitär, Malerarbeiten. Faire Preise ✓ Schnelle Termine ✓ 24h Notdienst ✓ Jetzt anfragen: +41 79 813 51 47",
    keywords: "handwerker zürich, handyman schweiz, renovierung zürich, reparaturservice, hausmeister zürich, 24h notdienst"
  },
  "/services": {
    title: "Handwerker-Leistungen Zürich | Elektrik, Sanitär, Renovierung – TipTop",
    description: "Professionelle Handwerkerleistungen in Zürich: Elektrik ⚡ Sanitär 🔧 Malerarbeiten 🎨 Möbelmontage 🪑 Renovierung. Faire Preise, schnelle Termine. Jetzt anfragen!",
    keywords: "elektriker zürich, sanitär zürich, malerarbeiten zürich, möbelmontage ikea, renovierung zürich, handwerker leistungen"
  },
  "/gallery": {
    title: "Referenzen & Projekte | Handwerker Zürich – TipTop Service",
    description: "Unsere abgeschlossenen Projekte: Badezimmer-Renovierung, Küchenmontage, Malerarbeiten, Elektroinstallationen. Überzeugen Sie sich von unserer Qualität!",
    keywords: "handwerker referenzen, renovierung vorher nachher, badezimmer renovierung zürich, küche montage, projekte handwerker"
  },
  "/reviews": {
    title: "Kundenbewertungen ★★★★★ 4.9/5 | TipTop Service Zürich",
    description: "Über 200 zufriedene Kunden bewerten uns mit 4.9/5 Sternen. Lesen Sie echte Erfahrungsberichte unserer Kunden aus Zürich und der Schweiz.",
    keywords: "handwerker bewertungen zürich, kundenmeinungen, erfahrungen tiptop service, handwerker empfehlung"
  },
  "/contact": {
    title: "Kontakt & Offerte | Handwerker Zürich – TipTop Service",
    description: "Kostenlose Beratung & Offerte anfordern. Online-Buchung möglich. Antwort innerhalb 30 Min. ☎ +41 79 813 51 47 oder Formular ausfüllen.",
    keywords: "handwerker kontakt zürich, offerte anfordern, kostenlose beratung, handwerker buchen online"
  }
};

export const useSEO = (customConfig?: SEOConfig) => {
  const location = useLocation();
  const { i18n } = useTranslation();
  
  useEffect(() => {
    const path = location.pathname;
    const config = { ...defaultConfig, ...pageConfigs[path], ...customConfig };
    const baseUrl = "https://tiptop-service.ch";
    const canonicalUrl = `${baseUrl}${config.canonicalPath || path}`;
    
    // Update document title
    document.title = config.title || defaultConfig.title!;
    
    // Update meta tags
    const updateMeta = (name: string, content: string, isProperty = false) => {
      const attr = isProperty ? "property" : "name";
      let meta = document.querySelector(`meta[${attr}="${name}"]`);
      if (!meta) {
        meta = document.createElement("meta");
        meta.setAttribute(attr, name);
        document.head.appendChild(meta);
      }
      meta.setAttribute("content", content);
    };
    
    // Primary meta tags
    updateMeta("description", config.description!);
    updateMeta("keywords", config.keywords!);
    
    // Open Graph
    updateMeta("og:title", config.title!, true);
    updateMeta("og:description", config.description!, true);
    updateMeta("og:url", canonicalUrl, true);
    updateMeta("og:type", config.type!, true);
    updateMeta("og:image", config.image!, true);
    
    // Twitter
    updateMeta("twitter:title", config.title!);
    updateMeta("twitter:description", config.description!);
    updateMeta("twitter:url", canonicalUrl);
    updateMeta("twitter:image", config.image!);
    
    // Update canonical link
    let canonical = document.querySelector('link[rel="canonical"]');
    if (!canonical) {
      canonical = document.createElement("link");
      canonical.setAttribute("rel", "canonical");
      document.head.appendChild(canonical);
    }
    canonical.setAttribute("href", canonicalUrl);
    
    // Update hreflang tags
    const languages = ["de", "en", "fr", "it"];
    languages.forEach(lang => {
      const hrefLang = `link[rel="alternate"][hreflang="${lang}"]`;
      let link = document.querySelector(hrefLang);
      if (!link) {
        link = document.createElement("link");
        link.setAttribute("rel", "alternate");
        link.setAttribute("hreflang", lang);
        document.head.appendChild(link);
      }
      link.setAttribute("href", `${canonicalUrl}?lang=${lang}`);
    });
    
    // x-default hreflang
    let xDefault = document.querySelector('link[rel="alternate"][hreflang="x-default"]');
    if (!xDefault) {
      xDefault = document.createElement("link");
      xDefault.setAttribute("rel", "alternate");
      xDefault.setAttribute("hreflang", "x-default");
      document.head.appendChild(xDefault);
    }
    xDefault.setAttribute("href", canonicalUrl);
    
    // Update html lang attribute
    document.documentElement.lang = i18n.language || "de";
    
  }, [location.pathname, customConfig, i18n.language]);
};

export default useSEO;