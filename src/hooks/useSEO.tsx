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
  title: "TipTop Service | Professioneller HandyMan Service in der Schweiz",
  description: "Professionelle Reparatur- und Wartungsdienste in der Schweiz. Renovierung, Malerarbeiten, Elektrik, Sanitär, Möbelmontage. ☎ +41 79 813 51 47",
  keywords: "handyman schweiz, reparatur zürich, renovierung, malerarbeiten, elektrik, sanitär",
  type: "website",
  image: "https://tiptop-service.ch/og-image.jpg"
};

const pageConfigs: Record<string, SEOConfig> = {
  "/": {
    title: "TipTop Service | Professioneller HandyMan Service in der Schweiz",
    description: "Professionelle Reparatur- und Wartungsdienste in der Schweiz. Von kleinen Reparaturen bis zu großen Renovierungen. Schweizer Qualität. ☎ +41 79 813 51 47",
    keywords: "handyman schweiz, reparatur zürich, renovierung schweiz, handwerker, hausmeister zürich"
  },
  "/services": {
    title: "Unsere Dienstleistungen | TipTop Service Schweiz",
    description: "Allgemeine Reparaturen, Malerarbeiten, Elektrik, Sanitär, Schreinerarbeiten, Möbelmontage, Renovierung. Professionelle Handwerkerleistungen in der Schweiz.",
    keywords: "reparaturen zürich, malerarbeiten schweiz, elektrik installation, sanitär reparatur, möbelmontage ikea, renovierung"
  },
  "/gallery": {
    title: "Arbeitsgalerie | TipTop Service - Unsere Projekte",
    description: "Sehen Sie Beispiele unserer abgeschlossenen Projekte. Badezimmer-Renovierungen, Küchen, Malerarbeiten und mehr. Schweizer Qualität.",
    keywords: "renovierung beispiele, handwerker portfolio, badezimmer renovierung, küche montage, malerarbeiten galerie"
  },
  "/reviews": {
    title: "Kundenbewertungen | TipTop Service - 4.9/5 Sterne",
    description: "Lesen Sie echte Bewertungen unserer zufriedenen Kunden. Mehr als 500 positive Bewertungen. 4.9/5 Sterne Durchschnitt.",
    keywords: "handyman bewertungen, kundenmeinungen, handwerker erfahrungen, tiptop service bewertung"
  },
  "/contact": {
    title: "Kontakt | TipTop Service - Kostenlose Beratung",
    description: "Kontaktieren Sie uns für eine kostenlose Beratung. Online-Buchung verfügbar. Antwort innerhalb von 30 Minuten. ☎ +41 79 813 51 47",
    keywords: "handyman kontakt, kostenlose beratung, online buchung, handwerker zürich kontakt"
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