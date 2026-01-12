import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Star, Quote, ArrowRight } from "lucide-react";

const testimonials = [
  {
    name: "Анна Мюллер",
    location: "Цюрих",
    rating: 5,
    text: "Отличный сервис! Марко починил все протечки в ванной за один визит. Очень пунктуальный и аккуратный мастер.",
    avatar: "AM",
  },
  {
    name: "Пьер Дюбуа",
    location: "Женева",
    rating: 5,
    text: "Заказывал сборку кухни IKEA. Работа выполнена безупречно, всё ровно и качественно. Рекомендую!",
    avatar: "PD",
  },
  {
    name: "Томас Шмидт",
    location: "Берн",
    rating: 5,
    text: "Полная реновация квартиры за 3 недели. Результат превзошёл ожидания. Профессионалы своего дела!",
    avatar: "TS",
  },
];

export const TestimonialsSection = () => {
  return (
    <section className="py-24 bg-secondary">
      <div className="container mx-auto px-4">
        <div className="text-center max-w-2xl mx-auto mb-16">
          <span className="text-accent font-semibold text-sm uppercase tracking-wider">
            Отзывы клиентов
          </span>
          <h2 className="text-3xl md:text-4xl font-bold text-foreground mt-3 mb-4">
            Что говорят наши клиенты
          </h2>
          <p className="text-muted-foreground">
            Более 500 довольных клиентов доверяют нам свои дома. 
            Их отзывы — лучшее подтверждение качества нашей работы.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {testimonials.map((testimonial, index) => (
            <div
              key={testimonial.name}
              className="bg-card rounded-2xl p-8 shadow-card relative"
              style={{ animationDelay: `${index * 0.1}s` }}
            >
              <Quote className="absolute top-6 right-6 w-10 h-10 text-accent/20" />
              
              <div className="flex mb-4">
                {[...Array(testimonial.rating)].map((_, i) => (
                  <Star key={i} className="w-5 h-5 fill-accent text-accent" />
                ))}
              </div>

              <p className="text-foreground mb-6 leading-relaxed">
                "{testimonial.text}"
              </p>

              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-full bg-accent/10 flex items-center justify-center">
                  <span className="text-accent font-semibold">{testimonial.avatar}</span>
                </div>
                <div>
                  <p className="font-semibold text-foreground">{testimonial.name}</p>
                  <p className="text-sm text-muted-foreground">{testimonial.location}</p>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="text-center mt-12">
          <Button variant="outline" size="lg" asChild>
            <Link to="/reviews">
              Все отзывы
              <ArrowRight className="w-4 h-4 ml-2" />
            </Link>
          </Button>
        </div>
      </div>
    </section>
  );
};
