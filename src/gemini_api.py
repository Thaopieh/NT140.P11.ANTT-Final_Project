import dataclasses
import os
import time
import random
from typing import Any, Dict, List, Tuple
from uuid import uuid1

import loguru
import google.generativeai as genai
from dotenv import load_dotenv
from google.generativeai.types import generation_types

# Load environment variables
load_dotenv()

# Configure logger
logger = loguru.logger
logger.remove()
logger.add(sink="./logs/gemini.log", level="WARNING", rotation="10 MB") # Added rotation


@dataclasses.dataclass
class Message:
    ask_id: str = None
    ask: dict = None
    answer: dict = None
    request_start_timestamp: float = None
    request_end_timestamp: float = None
    time_escaped: float = None


@dataclasses.dataclass
class Conversation:
    conversation_id: str = None
    chat_instance: Any = None
    message_list: List[Message] = dataclasses.field(default_factory=list)

    def __hash__(self):
        return hash(self.conversation_id)

    def __eq__(self, other):
        if not isinstance(other, Conversation):
            return False
        return self.conversation_id == other.conversation_id


class GeminiConfig:
    def __init__(self, model, api_key):
        self.gemini_key = api_key
        self.log_dir = "./logs"
        self.default_model = model


class LLMAPI:
    def __init__(self, config: GeminiConfig):
        self.config = config
        genai.configure(api_key=config.gemini_key)
        self.conversation_dict: Dict[str, Conversation] = {}
        os.makedirs(self.config.log_dir, exist_ok=True)


    def send_new_message(self, message: str) -> Tuple[str, str]:
        conversation_id = str(uuid1())
        start_time = time.time()

        try:
            model = genai.GenerativeModel(self.config.default_model)
            chat = model.start_chat(history=[{"role": "user", "parts": [{"text": message}]}]) #Corrected message format
            response = self.send_message_with_retry(chat, message) # Use retry function here

            if not response:
                raise RuntimeError("Failed to get response from Gemini API")

            conversation = Conversation(conversation_id=conversation_id, chat_instance=chat)
            new_message = Message(
                ask_id=str(uuid1()),
                ask={"role": "user", "content": message},
                answer={"role": "assistant", "content": response},
                request_start_timestamp=start_time,
                request_end_timestamp=time.time(),
                time_escaped=time.time() - start_time,
            )
            conversation.message_list.append(new_message)
            self.conversation_dict[conversation_id] = conversation
            logger.info(f"New conversation created: {conversation_id}")
            return response, conversation_id

        except Exception as e:
            logger.exception(f"Error creating new conversation: {e}")
            raise


    def send_message(self, message: str, conversation_id: str) -> str:
        if conversation_id not in self.conversation_dict:
            raise ValueError(f"Conversation ID {conversation_id} not found.")
        conversation = self.conversation_dict[conversation_id]
        chat = conversation.chat_instance
        start_time = time.time()

        try:
            response = self.send_message_with_retry(chat, message)
            if not response:
                raise RuntimeError("Failed to get a response from Gemini API")

            new_message = Message(
                ask_id=str(uuid1()),
                ask={"role": "user", "content": message},
                answer={"role": "assistant", "content": response},
                request_start_timestamp=start_time,
                request_end_timestamp=time.time(),
                time_escaped=time.time() - start_time,
            )
            conversation.message_list.append(new_message)
            self.conversation_dict[conversation_id] = conversation
            return response

        except Exception as e:
            logger.exception(f"Error sending message: {e}")
            raise



    def send_message_with_retry(self, chat, message, max_retries=5, base_delay=2):
        retries = 0
        while retries < max_retries:
            try:
                start_time = time.time()
                response = chat.send_message(message, stream=True)
                response.resolve()
                end_time = time.time()
                logger.info(f"API call took {end_time - start_time:.2f} seconds")

                if response and hasattr(response, 'text'):
                    logger.debug(f"Response text: {''.join(chunk.text for chunk in response)}")
                    return "".join(chunk.text for chunk in response)
                else:
                    logger.error("Invalid response received from Gemini API.")
                    raise RuntimeError("Invalid Gemini API response.") #more specific error message

            except generation_types.StopCandidateException as e:
                logger.error(f"StopCandidateException (retrying): {e}. Content: {getattr(e, 'content', 'N/A')}")
            except generation_types.BrokenResponseError as e:
                logger.exception(f"BrokenResponseError (retrying): {e}")
            except Exception as e:
                logger.exception(f"Unexpected error (retrying): {e}")

            delay = base_delay * (2**retries) + random.uniform(0, base_delay * (2**retries)) #better jitter
            logger.warning(f"Retrying in {delay:.2f} seconds (retry {retries + 1}/{max_retries})")
            time.sleep(delay)
            retries += 1

        logger.error(f"Maximum retries ({max_retries}) exceeded. Giving up.")
        return None



