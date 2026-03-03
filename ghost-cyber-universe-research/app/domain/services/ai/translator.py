from typing import Dict, Optional
import logging
from langdetect import detect, LangDetectException

logger = logging.getLogger(__name__)

# Import conditionnel
try:
    from deep_translator import GoogleTranslator
    TRANSLATOR_AVAILABLE = True
except ImportError:
    TRANSLATOR_AVAILABLE = False
    logger.warning("deep-translator not available. Translation disabled.")


class MultilingualTranslator:
    """Traducteur multilingue pour menaces cybersécurité"""
    
    SUPPORTED_LANGUAGES = {
        "fr": "Français",
        "en": "English",
        "es": "Español",
        "ar": "العربية",
        "de": "Deutsch",
        "it": "Italiano",
        "pt": "Português",
        "ru": "Русский",
        "zh-CN": "中文",
        "ja": "日本語"
    }
    
    def __init__(self):
        self.available = TRANSLATOR_AVAILABLE
        self.cache = {}  # Cache simple pour éviter les traductions répétées
    
    async def translate_threat(
        self,
        title: str,
        description: str,
        summary: Optional[str],
        target_language: str = "fr",
        source_language: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Traduit une menace vers la langue cible
        
        Args:
            title: Titre
            description: Description
            summary: Résumé (optionnel)
            target_language: Langue cible (code ISO)
            source_language: Langue source (auto-détection si None)
            
        Returns:
            Dict avec les traductions
        """
        if not self.available:
            return {
                "title": title,
                "description": description,
                "summary": summary or "",
                "source_language": "unknown",
                "target_language": target_language
            }
        
        # Détecter la langue source
        if not source_language:
            source_language = self.detect_language(title + " " + description)
        
        # Si déjà dans la langue cible, pas besoin de traduire
        if source_language == target_language:
            return {
                "title": title,
                "description": description,
                "summary": summary or "",
                "source_language": source_language,
                "target_language": target_language
            }
        
        try:
            # Créer le traducteur
            translator = GoogleTranslator(
                source=source_language,
                target=target_language
            )
            
            # Traduire chaque champ
            translated_title = self._translate_text(translator, title)
            translated_description = self._translate_text(translator, description)
            translated_summary = ""
            
            if summary:
                translated_summary = self._translate_text(translator, summary)
            
            return {
                "title": translated_title,
                "description": translated_description,
                "summary": translated_summary,
                "source_language": source_language,
                "target_language": target_language
            }
            
        except Exception as e:
            logger.error(f"Translation error: {str(e)}")
            return {
                "title": title,
                "description": description,
                "summary": summary or "",
                "source_language": source_language,
                "target_language": target_language,
                "error": str(e)
            }
    
    def _translate_text(self, translator, text: str, chunk_size: int = 4500) -> str:
        """
        Traduit un texte en gérant les limites de taille
        
        Args:
            translator: Instance du traducteur
            text: Texte à traduire
            chunk_size: Taille maximale des chunks
            
        Returns:
            str: Texte traduit
        """
        if not text:
            return ""
        
        # Vérifier le cache
        cache_key = f"{text[:100]}_{translator.source}_{translator.target}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        # Si le texte est court, traduire directement
        if len(text) <= chunk_size:
            try:
                result = translator.translate(text)
                self.cache[cache_key] = result
                return result
            except Exception as e:
                logger.error(f"Translation failed: {str(e)}")
                return text
        
        # Sinon, diviser en chunks
        chunks = self._split_text(text, chunk_size)
        translated_chunks = []
        
        for chunk in chunks:
            try:
                translated = translator.translate(chunk)
                translated_chunks.append(translated)
            except Exception as e:
                logger.error(f"Chunk translation failed: {str(e)}")
                translated_chunks.append(chunk)
        
        result = " ".join(translated_chunks)
        self.cache[cache_key] = result
        
        return result
    
    def _split_text(self, text: str, chunk_size: int) -> list:
        """Divise un texte en chunks tout en préservant les phrases"""
        # Diviser par phrases
        sentences = text.replace("! ", "!<split>").replace("? ", "?<split>").replace(". ", ".<split>").split("<split>")
        
        chunks = []
        current_chunk = ""
        
        for sentence in sentences:
            if len(current_chunk) + len(sentence) <= chunk_size:
                current_chunk += sentence + " "
            else:
                if current_chunk:
                    chunks.append(current_chunk.strip())
                current_chunk = sentence + " "
        
        if current_chunk:
            chunks.append(current_chunk.strip())
        
        return chunks
    
    def detect_language(self, text: str) -> str:
        """
        Détecte la langue d'un texte
        
        Args:
            text: Texte à analyser
            
        Returns:
            str: Code langue ISO (ex: 'fr', 'en')
        """
        try:
            # Utiliser seulement le début du texte pour la détection
            sample = text[:1000] if len(text) > 1000 else text
            lang = detect(sample)
            return lang
        except LangDetectException:
            return "en"  # Default to English
        except Exception as e:
            logger.error(f"Language detection error: {str(e)}")
            return "en"
    
    async def translate_multiple(
        self,
        texts: Dict[str, str],
        target_languages: list,
        source_language: Optional[str] = None
    ) -> Dict[str, Dict[str, str]]:
        """
        Traduit plusieurs textes vers plusieurs langues
        
        Args:
            texts: Dict de textes {"title": "...", "description": "..."}
            target_languages: Liste de langues cibles
            source_language: Langue source (auto-détection si None)
            
        Returns:
            Dict: {lang_code: {field: translated_text}}
        """
        results = {}
        
        for lang in target_languages:
            if lang not in self.SUPPORTED_LANGUAGES:
                logger.warning(f"Unsupported language: {lang}")
                continue
            
            translation = await self.translate_threat(
                title=texts.get("title", ""),
                description=texts.get("description", ""),
                summary=texts.get("summary"),
                target_language=lang,
                source_language=source_language
            )
            
            results[lang] = translation
        
        return results
    
    def clear_cache(self):
        """Vide le cache de traduction"""
        self.cache.clear()
        logger.info("Translation cache cleared")


# Instance globale
translator = MultilingualTranslator()

