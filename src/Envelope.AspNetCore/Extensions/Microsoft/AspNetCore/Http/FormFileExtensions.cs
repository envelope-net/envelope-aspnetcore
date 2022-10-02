namespace Envelope.Extensions;

public static class FormFileExtensions
{
	public static Envelope.Web.FormFile ToFormFile(this Microsoft.AspNetCore.Http.IFormFile formFile)
	{
		if (formFile == null)
			throw new ArgumentNullException(nameof(formFile));

		return new Envelope.Web.FormFile()
		{
			Content = formFile.OpenReadStream(),
			ContentType = formFile.ContentType,
			FileName = formFile.FileName,
			Length = formFile.Length
		};
	}

	public static async Task<Envelope.Web.FormFile> ToFormFileAsync(
		this Microsoft.AspNetCore.Http.IFormFile formFile,
		Stream targetStreamCopyTo,
		CancellationToken cancellationToken = default)
	{
		if (formFile == null)
			throw new ArgumentNullException(nameof(formFile));
		if (targetStreamCopyTo == null)
			throw new ArgumentNullException(nameof(targetStreamCopyTo));

		await formFile.CopyToAsync(targetStreamCopyTo, cancellationToken);

		return new Envelope.Web.FormFile()
		{
			Content = targetStreamCopyTo,
			ContentType = formFile.ContentType,
			FileName = formFile.FileName,
			Length = formFile.Length
		};
	}

	public static Microsoft.AspNetCore.Http.IFormFile ToFormFile(this Envelope.Web.FormFile formFile)
	{
		if (formFile == null)
			throw new ArgumentNullException(nameof(formFile));

		if (string.IsNullOrWhiteSpace(formFile.FileName))
			throw new InvalidOperationException($"{nameof(formFile.FileName)} == null");

		var stream = formFile.OpenReadStream();
		if (stream == null)
			throw new InvalidOperationException($"{nameof(stream)} == null");

		return new Microsoft.AspNetCore.Http.FormFile(stream, 0, stream.Length, formFile.FileName, formFile.FileName)
		{
			ContentType = formFile.ContentType ?? string.Empty,
		};
	}

	public static async Task<Microsoft.AspNetCore.Http.IFormFile> ToFormFileAsync(
		this Envelope.Web.FormFile formFile,
		Stream targetStreamCopyTo,
		CancellationToken cancellationToken = default)
	{
		if (formFile == null)
			throw new ArgumentNullException(nameof(formFile));

		if (string.IsNullOrWhiteSpace(formFile.FileName))
			throw new InvalidOperationException($"{nameof(formFile.FileName)} == null");

		await formFile.CopyToAsync(targetStreamCopyTo, cancellationToken);

		return new Microsoft.AspNetCore.Http.FormFile(targetStreamCopyTo, 0, targetStreamCopyTo.Length, formFile.FileName, formFile.FileName)
		{
			ContentType = formFile.ContentType ?? string.Empty,
		};
	}
}
