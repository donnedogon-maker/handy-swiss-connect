import { useState } from "react";
import { Navbar } from "@/components/layout/Navbar";
import { Footer } from "@/components/layout/Footer";
import { useTranslation } from "react-i18next";
import { useSEO } from "@/hooks/useSEO";
import { X } from "lucide-react";

import galleryBathroom from "@/assets/gallery-bathroom.jpg";
import galleryKitchen from "@/assets/gallery-kitchen.jpg";
import galleryTerrace from "@/assets/gallery-terrace.jpg";
import galleryPainting from "@/assets/gallery-painting.jpg";
import galleryElectrical from "@/assets/gallery-electrical.jpg";
import galleryFurniture from "@/assets/gallery-furniture.jpg";
import galleryCleaning from "@/assets/gallery-cleaning.jpg";
import galleryLivingRoom from "@/assets/gallery-living-room.jpg";
import galleryPlumbing from "@/assets/gallery-plumbing.jpg";

const categoryKeys = ["all", "bathrooms", "kitchens", "terraces", "painting", "electrical", "furniture", "cleaning", "plumbing"];

const galleryItems = [
  { id: 1, image: galleryBathroom, categoryKey: "bathrooms", titleKey: "bathroom", locationKey: "zurich" },
  { id: 2, image: galleryKitchen, categoryKey: "kitchens", titleKey: "kitchen", locationKey: "geneva" },
  { id: 3, image: galleryTerrace, categoryKey: "terraces", titleKey: "terrace", locationKey: "bern" },
  { id: 4, image: galleryPainting, categoryKey: "painting", titleKey: "painting", locationKey: "basel" },
  { id: 5, image: galleryElectrical, categoryKey: "electrical", titleKey: "electrical", locationKey: "lausanne" },
  { id: 6, image: galleryFurniture, categoryKey: "furniture", titleKey: "furniture", locationKey: "lucerne" },
  { id: 7, image: galleryCleaning, categoryKey: "cleaning", titleKey: "cleaning", locationKey: "lugano" },
  { id: 8, image: galleryLivingRoom, categoryKey: "painting", titleKey: "livingRoom", locationKey: "zug" },
  { id: 9, image: galleryPlumbing, categoryKey: "plumbing", titleKey: "plumbing", locationKey: "zurich" },
];

const Gallery = () => {
  const { t } = useTranslation();
  useSEO();
  const [activeCategory, setActiveCategory] = useState("all");
  const [lightboxImage, setLightboxImage] = useState<string | null>(null);

  const filteredItems = activeCategory === "all"
    ? galleryItems
    : galleryItems.filter((item) => item.categoryKey === activeCategory);

  return (
    <div className="min-h-screen">
      <Navbar />
      <main className="pt-20">
        {/* Hero */}
        <section className="py-20 bg-primary">
          <div className="container mx-auto px-4 text-center">
            <h1 className="text-4xl md:text-5xl font-bold text-primary-foreground mb-6">
              {t("gallery.title")}
            </h1>
            <p className="text-lg text-primary-foreground/80 max-w-2xl mx-auto">
              {t("gallery.description")}
            </p>
          </div>
        </section>

        {/* Filter */}
        <section className="py-8 bg-background border-b border-border sticky top-20 z-40">
          <div className="container mx-auto px-4">
            <div className="flex flex-wrap gap-3 justify-center">
              {categoryKeys.map((key) => (
                <button
                  key={key}
                  onClick={() => setActiveCategory(key)}
                  className={`px-5 py-2.5 rounded-full text-sm font-medium transition-all ${
                    activeCategory === key
                      ? "bg-accent text-accent-foreground"
                      : "bg-muted text-muted-foreground hover:bg-muted/80"
                  }`}
                >
                  {t(`gallery.categories.${key}`)}
                </button>
              ))}
            </div>
          </div>
        </section>

        {/* Gallery Grid */}
        <section className="py-16 bg-background">
          <div className="container mx-auto px-4">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {filteredItems.map((item) => (
                <div
                  key={item.id}
                  className="group relative rounded-2xl overflow-hidden shadow-card cursor-pointer"
                  onClick={() => setLightboxImage(item.image)}
                >
                  <div className="aspect-square">
                    <img
                      src={item.image}
                      alt={t(`gallery.items.${item.titleKey}`)}
                      className="w-full h-full object-cover group-hover:scale-110 transition-transform duration-500"
                    />
                  </div>
                  <div className="absolute inset-0 bg-gradient-to-t from-primary/90 via-primary/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                    <div className="absolute bottom-0 left-0 right-0 p-6">
                      <h3 className="text-lg font-semibold text-primary-foreground mb-1">
                        {t(`gallery.items.${item.titleKey}`)}
                      </h3>
                      <p className="text-sm text-primary-foreground/70">
                        {t(`gallery.locations.${item.locationKey}`)}
                      </p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Lightbox */}
        {lightboxImage && (
          <div
            className="fixed inset-0 z-50 bg-primary/95 flex items-center justify-center p-4"
            onClick={() => setLightboxImage(null)}
          >
            <button
              className="absolute top-6 right-6 w-12 h-12 rounded-full bg-primary-foreground/10 flex items-center justify-center hover:bg-primary-foreground/20 transition-colors"
              onClick={() => setLightboxImage(null)}
            >
              <X className="w-6 h-6 text-primary-foreground" />
            </button>
            <img
              src={lightboxImage}
              alt="Gallery"
              className="max-w-full max-h-[85vh] rounded-xl"
              onClick={(e) => e.stopPropagation()}
            />
          </div>
        )}
      </main>
      <Footer />
    </div>
  );
};

export default Gallery;