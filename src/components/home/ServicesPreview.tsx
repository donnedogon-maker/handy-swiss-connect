import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { 
  Wrench, 
  Paintbrush, 
  Plug, 
  Droplets, 
  Hammer, 
  Home,
  ArrowRight 
} from "lucide-react";

const services = [
  {
    icon: Wrench,
    title: "Общий ремонт",
    description: "Мелкий и средний ремонт по дому, сборка мебели, навешивание полок",
  },
  {
    icon: Paintbrush,
    title: "Малярные работы",
    description: "Покраска стен, потолков, фасадов. Декоративная отделка",
  },
  {
    icon: Plug,
    title: "Электрика",
    description: "Установка розеток, выключателей, светильников. Диагностика",
  },
  {
    icon: Droplets,
    title: "Сантехника",
    description: "Ремонт и установка сантехники, устранение протечек",
  },
  {
    icon: Hammer,
    title: "Плотницкие работы",
    description: "Работа с деревом, установка дверей, ремонт паркета",
  },
  {
    icon: Home,
    title: "Реновация",
    description: "Полная реновация квартир и домов под ключ",
  },
];

export const ServicesPreview = () => {
  return (
    <section className="py-24 bg-background">
      <div className="container mx-auto px-4">
        <div className="text-center max-w-2xl mx-auto mb-16">
          <span className="text-accent font-semibold text-sm uppercase tracking-wider">
            Наши услуги
          </span>
          <h2 className="text-3xl md:text-4xl font-bold text-foreground mt-3 mb-4">
            Комплексные решения для вашего дома
          </h2>
          <p className="text-muted-foreground">
            Мы предоставляем широкий спектр услуг по ремонту и обслуживанию дома. 
            Каждый проект выполняется с высочайшим качеством.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {services.map((service, index) => (
            <div
              key={service.title}
              className="group bg-card rounded-2xl p-8 shadow-card hover:shadow-card-hover transition-all duration-300 hover:-translate-y-1"
              style={{ animationDelay: `${index * 0.1}s` }}
            >
              <div className="w-14 h-14 rounded-xl bg-accent/10 flex items-center justify-center mb-6 group-hover:bg-accent group-hover:scale-110 transition-all duration-300">
                <service.icon className="w-7 h-7 text-accent group-hover:text-accent-foreground transition-colors" />
              </div>
              <h3 className="text-xl font-semibold text-foreground mb-3">
                {service.title}
              </h3>
              <p className="text-muted-foreground text-sm leading-relaxed">
                {service.description}
              </p>
            </div>
          ))}
        </div>

        <div className="text-center mt-12">
          <Button variant="outline" size="lg" asChild>
            <Link to="/services">
              Все услуги
              <ArrowRight className="w-4 h-4 ml-2" />
            </Link>
          </Button>
        </div>
      </div>
    </section>
  );
};
