import { Component, OnInit } from '@angular/core';
import { take } from 'rxjs';
import { User } from 'src/app/_models/user';
import { Member } from 'src/app/_modules/member';
import { AccountService } from 'src/app/_services/account.service';
import { MembersService } from 'src/app/_services/members.service';

@Component({
  selector: 'app-member-edit',
  templateUrl: './member-edit.component.html',
  styleUrls: ['./member-edit.component.css']
})
export class MemberEditComponent implements OnInit {

  member: Member | undefined;
  user: User | null = null;

  constructor(private accountService:AccountService, private memberService: MembersService) {

    this.accountService.currentUser$.pipe(take(1)).subscribe({
      next:(user)=> {
        this.user = user;
      },
      error: (error) => { console.log(error) }
    });

   }

  ngOnInit(): void {
    this.loadMember();
  }

  loadMember(){
    if(!this.user) return;
    this.memberService.getMember(this.user.username).subscribe({
      next: (memeber) => { this.member = memeber }
    });
  }

}