/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

interface Service {
  icon: string;
  title: string;
  description: string;
  price: string;
}

const services: Service[] = [
  {
    icon: '✂️',
    title: 'Precision Cuts',
    description: 'Expert haircuts tailored to your face shape and style preferences',
    price: 'From $35',
  },
  {
    icon: '✨',
    title: 'Styling & Finishing',
    description: 'Professional styling with premium products for lasting results',
    price: 'From $25',
  },
  {
    icon: '👥',
    title: 'Consultation',
    description: 'Personal style consultation to find your perfect look',
    price: 'From $15',
  },
  {
    icon: '🏆',
    title: 'Full Service',
    description: 'Complete grooming package for the modern gentleman',
    price: 'From $75',
  },
];

export default function ServicesSection() {
  return (
    <section className="py-16 bg-gray-50">
      <div className="container mx-auto px-4">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold text-gray-900 mb-4">Our Services</h2>
          <p className="text-gray-600 max-w-2xl mx-auto">
            Professional grooming services tailored to bring out the best in every gentleman.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {services.map((service, index) => (
            <div key={index} className="bg-white p-6 rounded-lg shadow-md hover:shadow-lg transition-shadow">
              <div className="flex flex-col items-center text-center">
                <div className="text-4xl mb-4">{service.icon}</div>
                <h3 className="text-xl font-semibold text-gray-900 mb-2">{service.title}</h3>
                <p className="text-gray-600 mb-4">{service.description}</p>
                <span className="text-blue-600 font-bold">{service.price}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
