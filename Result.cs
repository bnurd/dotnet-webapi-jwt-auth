namespace dotnet_webapi_jwt_auth;

public interface IResult
{
    bool Success { get; set; }
    string Message { get; set; }
}

public class SuccessResult : IResult
{
    public SuccessResult(string message = "")
    {
        Message = message;
    }

    public bool Success { get; set; } = true;
    public string Message { get; set; }
}

public class ErrorResult : IResult
{

    public ErrorResult(string message = "")
    {
        Message = message;
    }

    public bool Success { get; set; } = false;
    public string Message { get; set; }
}

public interface IDataResult<T> : IResult
{
    public bool Success { get; set; }
    public string Message { get; set; }
    public T Data { get; set; }
}

public class SuccessDataResult<T> : IDataResult<T>
{
    public SuccessDataResult(T data, string message = "")
    {
        Message = message;
        Data = data;
    }

    public bool Success { get; set; } = true;
    public string Message { get; set; }
    public T Data { get; set; }
}

public class ErrorDataResult<T> : IDataResult<T>
{
    public ErrorDataResult(string message = "")
    {
        Message = message;

    }

    public bool Success { get; set; } = false;
    public string Message { get; set; }
    public T Data { get; set; }
}