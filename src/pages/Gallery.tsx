import { useState } from "react";
import { Navbar } from "@/components/layout/Navbar";
import { Footer } from "@/components/layout/Footer";
import { ChatWidget } from "@/components/chat/ChatWidget";
import { X } from "lucide-react";

import galleryBathroom from "@/assets/gallery-bathroom.jpg";
import galleryKitchen from "@/assets/gallery-kitchen.jpg";
import galleryTerrace from "@/assets/gallery-terrace.jpg";
import galleryPainting from "@/assets/gallery-painting.jpg";
import galleryElectrical from "@/assets/gallery-electrical.jpg";
import galleryFurniture from "@/assets/gallery-furniture.jpg";

const categories = ["Все", "Ванные", "Кухни", "Террасы", "Покраска", "Электрика", "Мебель"];

const galleryItems = [
  { id: 1, image: galleryBathroom, category: "Ванные", title: "Реновация ванной комнаты", location: "Цюрих" },
  { id: 2, image: galleryKitchen, category: "Кухни", title: "Установка кухни", location: "Женева" },
  { id: 3, image: galleryTerrace, category: "Террасы", title: "Строительство террасы", location: "Берн" },
  { id: 4, image: galleryPainting, category: "Покраска", title: "Покраска гостиной", location: "Базель" },
  { id: 5, image: galleryElectrical, category: "Электрика", title: "Установка освещения", location: "Лозанна" },
  { id: 6, image: galleryFurniture, category: "Мебель", title: "Сборка мебели", location: "Люцерн" },
];

const Gallery = () => {
  const [activeCategory, setActiveCategory] = useState("Все");
  const [lightboxImage, setLightboxImage] = useState<string | null>(null);

  const filteredItems = activeCategory === "Все"
    ? galleryItems
    : galleryItems.filter((item) => item.category === activeCategory);

  return (
    <div className="min-h-screen">
      <Navbar />
      <main className="pt-20">
        {/* Hero */}
        <section className="py-20 bg-primary">
          <div className="container mx-auto px-4 text-center">
            <h1 className="text-4xl md:text-5xl font-bold text-primary-foreground mb-6">
              Галерея работ
            </h1>
            <p className="text-lg text-primary-foreground/80 max-w-2xl mx-auto">
              Посмотрите примеры наших проектов. Каждая работа выполнена 
              с вниманием к деталям и швейцарским качеством.
            </p>
          </div>
        </section>

        {/* Filter */}
        <section className="py-8 bg-background border-b border-border sticky top-20 z-40">
          <div className="container mx-auto px-4">
            <div className="flex flex-wrap gap-3 justify-center">
              {categories.map((category) => (
                <button
                  key={category}
                  onClick={() => setActiveCategory(category)}
                  className={`px-5 py-2.5 rounded-full text-sm font-medium transition-all ${
                    activeCategory === category
                      ? "bg-accent text-accent-foreground"
                      : "bg-muted text-muted-foreground hover:bg-muted/80"
                  }`}
                >
                  {category}
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
                      alt={item.title}
                      className="w-full h-full object-cover group-hover:scale-110 transition-transform duration-500"
                    />
                  </div>
                  <div className="absolute inset-0 bg-gradient-to-t from-primary/90 via-primary/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                    <div className="absolute bottom-0 left-0 right-0 p-6">
                      <h3 className="text-lg font-semibold text-primary-foreground mb-1">
                        {item.title}
                      </h3>
                      <p className="text-sm text-primary-foreground/70">{item.location}</p>
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
      <ChatWidget />
    </div>
  );
};

export default Gallery;
