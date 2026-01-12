import { Navbar } from "@/components/layout/Navbar";
import { Footer } from "@/components/layout/Footer";
import { ChatWidget } from "@/components/chat/ChatWidget";
import { Button } from "@/components/ui/button";
import { Link } from "react-router-dom";
import { 
  Wrench, 
  Paintbrush, 
  Plug, 
  Droplets, 
  Hammer, 
  Home,
  Sofa,
  Shield,
  Truck,
  ArrowRight,
  CheckCircle2
} from "lucide-react";

const services = [
  {
    icon: Wrench,
    title: "Общий ремонт",
    description: "Мелкий и средний ремонт по дому. Починка, сборка мебели, навешивание полок, картин, зеркал, карнизов.",
    features: ["Сборка мебели IKEA", "Установка карнизов", "Навешивание полок", "Мелкий ремонт"],
    price: "от 80 CHF/час",
  },
  {
    icon: Paintbrush,
    title: "Малярные работы",
    description: "Профессиональная покраска стен, потолков и фасадов. Декоративная отделка и реставрация.",
    features: ["Покраска стен", "Декоративная штукатурка", "Поклейка обоев", "Реставрация"],
    price: "от 45 CHF/м²",
  },
  {
    icon: Plug,
    title: "Электрика",
    description: "Установка и ремонт электрооборудования. Диагностика неисправностей, замена проводки.",
    features: ["Установка розеток", "Монтаж освещения", "Диагностика", "Замена проводки"],
    price: "от 90 CHF/час",
  },
  {
    icon: Droplets,
    title: "Сантехника",
    description: "Полный спектр сантехнических работ. Установка, ремонт, устранение протечек.",
    features: ["Установка сантехники", "Устранение протечек", "Чистка канализации", "Замена труб"],
    price: "от 85 CHF/час",
  },
  {
    icon: Hammer,
    title: "Плотницкие работы",
    description: "Качественная работа с деревом. Установка дверей, ремонт паркета, изготовление мебели.",
    features: ["Установка дверей", "Ремонт паркета", "Изготовление мебели", "Реставрация"],
    price: "от 95 CHF/час",
  },
  {
    icon: Home,
    title: "Реновация под ключ",
    description: "Полная реновация квартир и домов. От проекта до финальной уборки — всё включено.",
    features: ["Дизайн-проект", "Черновые работы", "Чистовая отделка", "Меблировка"],
    price: "по договорённости",
  },
  {
    icon: Sofa,
    title: "Сборка мебели",
    description: "Профессиональная сборка мебели любой сложности. IKEA, кухни, гардеробные системы.",
    features: ["Мебель IKEA", "Кухни", "Гардеробные", "Детская мебель"],
    price: "от 60 CHF/час",
  },
  {
    icon: Shield,
    title: "Безопасность дома",
    description: "Установка систем безопасности, замков, домофонов и видеонаблюдения.",
    features: ["Замена замков", "Домофоны", "Видеонаблюдение", "Датчики"],
    price: "от 100 CHF/час",
  },
  {
    icon: Truck,
    title: "Переезды",
    description: "Помощь с переездом: упаковка, транспортировка, сборка/разборка мебели на новом месте.",
    features: ["Упаковка", "Транспортировка", "Разборка мебели", "Сборка на месте"],
    price: "от 150 CHF",
  },
];

const Services = () => {
  return (
    <div className="min-h-screen">
      <Navbar />
      <main className="pt-20">
        {/* Hero */}
        <section className="py-20 bg-primary">
          <div className="container mx-auto px-4 text-center">
            <h1 className="text-4xl md:text-5xl font-bold text-primary-foreground mb-6">
              Наши услуги
            </h1>
            <p className="text-lg text-primary-foreground/80 max-w-2xl mx-auto">
              Полный спектр услуг по ремонту и обслуживанию дома. 
              Швейцарское качество и профессиональный подход.
            </p>
          </div>
        </section>

        {/* Services Grid */}
        <section className="py-24 bg-background">
          <div className="container mx-auto px-4">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
              {services.map((service) => (
                <div
                  key={service.title}
                  className="group bg-card rounded-2xl p-8 shadow-card hover:shadow-card-hover transition-all duration-300"
                >
                  <div className="w-16 h-16 rounded-xl bg-accent/10 flex items-center justify-center mb-6 group-hover:bg-accent transition-colors">
                    <service.icon className="w-8 h-8 text-accent group-hover:text-accent-foreground transition-colors" />
                  </div>

                  <h3 className="text-xl font-semibold text-foreground mb-3">
                    {service.title}
                  </h3>
                  <p className="text-muted-foreground text-sm mb-6 leading-relaxed">
                    {service.description}
                  </p>

                  <ul className="space-y-2 mb-6">
                    {service.features.map((feature) => (
                      <li key={feature} className="flex items-center gap-2 text-sm text-foreground">
                        <CheckCircle2 className="w-4 h-4 text-accent flex-shrink-0" />
                        {feature}
                      </li>
                    ))}
                  </ul>

                  <div className="flex items-center justify-between pt-6 border-t border-border">
                    <span className="text-accent font-semibold">{service.price}</span>
                    <Button variant="ghost" size="sm" asChild>
                      <Link to="/contact">
                        Заказать
                        <ArrowRight className="w-4 h-4 ml-1" />
                      </Link>
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="py-16 bg-secondary">
          <div className="container mx-auto px-4 text-center">
            <h2 className="text-2xl md:text-3xl font-bold text-foreground mb-4">
              Не нашли нужную услугу?
            </h2>
            <p className="text-muted-foreground mb-8">
              Свяжитесь с нами — мы решим любую задачу по дому!
            </p>
            <Button variant="accent" size="lg" asChild>
              <Link to="/contact">
                Связаться с нами
                <ArrowRight className="w-4 h-4 ml-2" />
              </Link>
            </Button>
          </div>
        </section>
      </main>
      <Footer />
      <ChatWidget />
    </div>
  );
};

export default Services;
