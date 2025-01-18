use anchor_lang::prelude::*;
//use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("DpEXv5eoKCKj6cd9RwVgqC9fGHqxqNc7TewSPtgXLoxD");  // Temporary ID

#[program]
pub mod quiz_game {
    use super::*;

    pub fn initialize_game(
        ctx: Context<InitializeGame>,
        bet_amount: u64,
        room_id: String,
    ) -> Result<()> {
        let game = &mut ctx.accounts.game;
        game.creator = ctx.accounts.creator.key();
        game.bet_amount = bet_amount;
        game.room_id = room_id;
        game.player_count = 1;
        game.is_active = true;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeGame<'info> {
    #[account(mut)]
    pub creator: Signer<'info>,
    #[account(
        init,
        payer = creator,
        space = 8 + 32 + 8 + 32 + 1 + 1
    )]
    pub game: Account<'info, Game>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Game {
    pub creator: Pubkey,
    pub bet_amount: u64,
    pub room_id: String,
    pub player_count: u8,
    pub is_active: bool,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Game is not active")]
    GameNotActive,
    #[msg("Game is full")]
    GameFull,
}