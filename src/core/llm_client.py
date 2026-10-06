import os
from langchain_core.language_models.chat_models import BaseChatModel
# Dùng langchain_openai hoặc các thư viện tương ứng cho từng model
# from langchain_openai import ChatOpenAI
# from langchain_anthropic import ChatAnthropic

def get_llm_client(model_name: str = "qwen-2.5-coder") -> BaseChatModel:
    """
    Khởi tạo và trả về LLM client dựa trên tên model được chọn.
    Mặc định sử dụng Qwen 2.5 Coder hoặc DeepSeek V3 cho các tác vụ code.
    """
    # TODO: Cấu hình API Keys trong file .env và thay thế bằng các provider thật.
    # Ví dụ với OpenAI tương thích API:
    # if "qwen" in model_name or "deepseek" in model_name:
    #     return ChatOpenAI(
    #         api_key=os.getenv("API_KEY"), 
    #         base_url=os.getenv("BASE_URL"),
    #         model=model_name
    #     )
    # elif "claude" in model_name:
    #     return ChatAnthropic(model=model_name, api_key=os.getenv("ANTHROPIC_API_KEY"))
    
    raise NotImplementedError("Cần cài đặt thư viện provider cụ thể và điền API KEY trong môi trường")

def invoke_llm(llm: BaseChatModel, prompt: str) -> str:
    """
    Hàm tiện ích để gọi LLM đơn giản.
    """
    response = llm.invoke(prompt)
    return response.content
