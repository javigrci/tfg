import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import en from './en.json'
import es from './es.json'

i18n
  .use(initReactI18next)
  .init({
    resources: {
      en: { translation: en },
      es: { translation: es },
    },
    // Leer preferencia guardada; inglés por defecto
    lng: localStorage.getItem('i18nextLng') ?? 'en',
    fallbackLng: 'en',
    interpolation: {
      escapeValue: false, // React ya escapa por defecto
    },
  })

export default i18n
