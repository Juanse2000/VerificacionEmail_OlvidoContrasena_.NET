using VerifyEmailForgotPassword.Data;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

/* Conexion al contexto de la base de datos */
builder.Services.AddDbContext<DataContext>();

builder.Services.AddCors(options =>
{
    options.AddPolicy("MiPoliticaCors", builder =>
    {
        builder.AllowAnyOrigin()
               .AllowAnyMethod()
               .AllowAnyHeader();
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors("MiPoliticaCors");

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
