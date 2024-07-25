using JwtAuthenticationLearning.Core.OtherObjects;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthenticationLearning.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = 
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

      

        

        [HttpGet]
        [Route("Get")]
        public IActionResult Get()
        {
            return Ok(Summaries);
        }


        [HttpGet]
        [Route("getWeatherByUser")]
        [Authorize(Roles = StaticUserRole.USER)]
        public IActionResult GetWeatherListByUser()
        {
            return Ok(Summaries);
        }


        [HttpGet]
        [Route("getWeatherByAdmin")]
        [Authorize(Roles = StaticUserRole.ADMIN)]
        public IActionResult GetWeatherListByAdmin()
        {
            return Ok(Summaries);
        }


        [HttpGet]
        [Route("getWeatherByOwner")]
        [Authorize(Roles = StaticUserRole.OWNER)]
        public IActionResult GetWeatherListByOwner()
        {
            return Ok(Summaries);
        }
    }
}
