using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Simple_WebAPI.Data;
using Simple_WebAPI.Models;

namespace Simple_WebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ApiUsersController : ControllerBase
    {
        private readonly TodolistContext _context;

        public ApiUsersController(TodolistContext context)
        {
            _context = context;
        }

        // GET: api/ApiUsers
        [HttpGet]
        public async Task<ActionResult<IEnumerable<ApiUser>>> GetApiUsers()
        {
            return await _context.ApiUsers.ToListAsync();
        }

        // GET: api/ApiUsers/5
        [HttpGet("{id}")]
        public async Task<ActionResult<ApiUser>> GetApiUser(int id)
        {
            var apiUser = await _context.ApiUsers.FindAsync(id);

            if (apiUser == null)
            {
                return NotFound();
            }

            return apiUser;
        }

        // PUT: api/ApiUsers/5
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPut("{id}")]
        public async Task<IActionResult> PutApiUser(int id, ApiUser apiUser)
        {
            if (id != apiUser.Id)
            {
                return BadRequest();
            }

            _context.Entry(apiUser).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!ApiUserExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return NoContent();
        }

        // POST: api/ApiUsers
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPost]
        public async Task<ActionResult<ApiUser>> PostApiUser(ApiUser apiUser)
        {
            _context.ApiUsers.Add(apiUser);
            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateException)
            {
                if (ApiUserExists(apiUser.Id))
                {
                    return Conflict();
                }
                else
                {
                    throw;
                }
            }

            return CreatedAtAction("GetApiUser", new { id = apiUser.Id }, apiUser);
        }

        // DELETE: api/ApiUsers/5
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteApiUser(int id)
        {
            var apiUser = await _context.ApiUsers.FindAsync(id);
            if (apiUser == null)
            {
                return NotFound();
            }

            _context.ApiUsers.Remove(apiUser);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        private bool ApiUserExists(int id)
        {
            return _context.ApiUsers.Any(e => e.Id == id);
        }
    }
}
